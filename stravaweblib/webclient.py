from base64 import b64decode
import cgi
from collections import namedtuple
from datetime import date, datetime
from itertools import zip_longest
import enum
import functools
import json
import time
from textwrap import dedent
from xml.sax.saxutils import escape, quoteattr

from bs4 import BeautifulSoup
import requests
import stravalib


__all__ = ["WebClient", "FrameType", "DataFormat", "ActivityFile"]


BASE_URL = "https://www.strava.com"
NENE_URL = "https://nene.strava.com"


ActivityFile = namedtuple("ActivityFile", ("filename", "content"))


def _iso8601(ts):
    return datetime.utcfromtimestamp(ts).isoformat() + 'Z'


# https://developers.strava.com/docs/uploads/
_tcx_sport_from_strava = {
    'Run': 'Running',
    'Ride': 'Biking',
    'Swim': 'Swimming',
    'Hike': 'Hiking',
    'Walk': 'Walking',
}
# https://stackoverflow.com/questions/61903437/what-do-the-strava-gpx-type-type-elements-mean
_gpx_type_from_strava = {
    'Run': '9',
    'Bike': '1',
    'Swim': '16',
    'Hike': '4',
    'Walk': '10',
}


class DataFormat(enum.Enum):
    ORIGINAL = "original"
    GPX = "gpx"
    TCX = "tcx"

    def __str__(self):
        return str(self.value)

    @classmethod
    def classify(cls, value):
        for x in cls:
            if x.value == str(value):
                return x
        raise ValueError("Invalid format '{}'".format(value))


class FrameType(enum.Enum):
    MOUNTAIN_BIKE = 1
    CROSS_BIKE = 2
    ROAD_BIKE = 3
    TIME_TRIAL_BIKE = 4

    def __str__(self):
        return str(self.name).replace("_", " ").title()


class WebClient(stravalib.Client):
    """
    An extension to the stravalib Client that fills in some of the gaps in
    the official API using web scraping.
    """

    def __init__(self, *args, **kwargs):
        # Docstring set manually after class definition

        jwt = kwargs.pop("jwt", None)
        email = kwargs.pop("email", None)
        password = kwargs.pop("password", None)

        self._csrf = kwargs.pop("csrf", None)

        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })

        if jwt:
            self._login_with_jwt(jwt)
        elif email and password:
            self._login_with_password(email, password)
        else:
            raise ValueError("'jwt' or both of 'email' and 'password' are required")

        # Init the normal stravalib client with remaining args
        super().__init__(*args, **kwargs)

        # Verify that REST API and Web API correspond to the same Strava user account
        if self.access_token is not None:
            rest_id = str(self.get_athlete().id)
            web_id = self._session.cookies.get('strava_remember_id')
            if rest_id != web_id:
                raise stravalib.exc.LoginFailed("API and web credentials are for different accounts")
        else:
            # REST API does not have an access_token (yet). Should we verify the match after
            # exchange_code_for_token()?
            pass

    @property
    def jwt(self):
        return self._session.cookies.get('strava_remember_token')

    @property
    def csrf(self):
        if not self._csrf:
            self._csrf = self._get_csrf_token()
        return self._csrf

    def _get_csrf_token(self):
        """Get a CSRF token

        Uses the about page because it's small and doesn't redirect based
        on if the client is logged in or not.
        """
        login_html = self._session.get("{}/about".format(BASE_URL)).text
        soup = BeautifulSoup(login_html, 'html.parser')

        try:
            head = soup.head
            csrf_param = head.find('meta', attrs={"name": "csrf-param"}).attrs['content']
            csrf_token = head.find('meta', attrs={"name": "csrf-token"}).attrs['content']
        except (AttributeError, KeyError):
            # "AttributeError: 'NoneType' object has no attr..." when failing
            # to find the tags.
            raise stravalib.exc.Fault("Couldn't find CSRF token")

        return {csrf_param: csrf_token}

    def _login_with_jwt(self, jwt):
        """Log in using the strava_remember_token (a JWT) from a previous session"""
        # The JWT's 'sub' key contains the id of the account. This must be
        # extracted and set as the 'strava_remember_id' cookie.
        try:
            payload = jwt.split('.')[1]  # header.payload.signature
            payload += "=" * (4 - len(payload) % 4)  # ensure correct padding
            data = json.loads(b64decode(payload))
        except Exception:
            raise ValueError("Failed to parse JWT payload")

        try:
            if data["exp"] < time.time():
                raise ValueError("JWT has expired")
            web_id = str(data["sub"])
        except KeyError:
            raise ValueError("Failed to extract required data from the JWT")

        self._session.cookies.set('strava_remember_id', web_id, domain='.strava.com', secure=True)
        self._session.cookies.set('strava_remember_token', jwt, domain='.strava.com', secure=True)

    def _login_with_password(self, email, password):
        """Log into the website using a username and password"""
        resp = self._session.post(
            "{}/session".format(BASE_URL),
            allow_redirects=False,
            data={
                "email": email,
                "password": password,
                "remember_me": "on",
                **self.csrf
            }
        )
        if not resp.is_redirect or resp.next.url == "{}/login".format(BASE_URL):
            raise stravalib.exc.LoginFailed("Couldn't log in to website, check creds")

    def delete_activity(self, activity_id):
        """
        Deletes the specified activity.

        :param activity_id: The activity to delete.
        :type activity_id: int
        """
        resp = self._session.post(
            "{}/activities/{}".format(BASE_URL, activity_id),
            allow_redirects=False,
            data={
                "_method": "delete",
                **self.csrf
            }
        )

        if not resp.is_redirect or resp.next.url != "{}/athlete/training".format(BASE_URL):
            raise stravalib.exc.Fault(
                "Failed to delete activity (status code: {})".format(resp.status_code),
            )

    def scrape_activity_data(self, activity_id, fmt=DataFormat.TCX):
        """
        Get a file containing the provided activity's data

        The returned data is scraped from the Strava web interface and
        various JSON streams that it uses, then converted into either
        GPX or TCX format.

        This allows extracting activity data for users other than the
        logged-in user.

        :param activity_id: The activity to retrieve.
        :type activity_id: int

        :param fmt: The format to request the data in
                    (defaults to DataFormat.TCX).
        :type fmt: :class:`DataFormat`
        """
        fmt = DataFormat.classify(fmt)

        # Open the HTML page for this activity. Then scrape title,
        # device, type, and approximate start time from it on a "best
        # effort" basis; don't fail if any/all of them can't be found.
        url = main_url = "{}/activities/{}".format(BASE_URL, activity_id)
        resp = self._session.get(url, allow_redirects=False)
        if resp.status_code != 200:
            raise stravalib.exc.Fault("Status code '{}' received when trying to "
                                      "scrape HTML for activity {}"
                                      "".format(resp.status_code, activity_id))

        soup = BeautifulSoup(resp.text, 'html5lib')
        tag = soup.find(class_="activity-name")
        activity_title = tag.text.strip() if tag else ""

        tag = soup.find(class_="device")
        device = tag.text.strip() if tag else ""

        # Page title looks like "Activity Name | Activity Type | Strava"
        tag = soup.find("title")
        activity_type = tag.text.split('|')[-2].strip() if tag and tag.text.count('|') >= 2 else "Other"

        start_time = 0
        for tag in soup.find_all('time'):
            try:
                # This timestamp is accurate only to one minute,
                # and it's in the timezone of the activity's
                # starting location. We could correct it by using
                # 'timezonefinder' and 'pytz' to infer the correct
                # timezone from the GPS location, or the user's
                # default location in the absence of GPS data.
                start_time = datetime.strptime(
                    tag.text.strip(), '%I:%M %p on %A, %B %d, %Y').timestamp()
                break
            except ValueError:
                pass

        # Request export_gpx (HEAD only) to get filename hint. The GPX export
        # for other users' activities includes only the route (lat/long) and
        # no timestamps or other data, so not very useful "as is."
        url = "{}/activities/{}/export_gpx".format(BASE_URL, activity_id)
        resp = self._session.head(url, allow_redirects=False, headers={'Referer': main_url})
        filename = self._strava_filename(resp, activity_id, fmt)
        if fmt == DataFormat.TCX and filename.endswith('.gpx'):
            filename = filename[:-4] + '.tcx'

        # Request streams JSON, used by Strava web UI to show map and
        # summary stats. We have to read the entire JSON and transpose
        # it in order to output it in any known format.
        now_ms = int(datetime.utcnow().timestamp() * 1000)
        streams = ('altitude', 'distance', 'time', 'latlng', 'heartrate', 'cadence')
        url = "{}/activities/{}/streams?_={}&{}".format(BASE_URL, activity_id, now_ms, '&'.join('&stream_types[]={}'.format(s) for s in streams))
        resp = self._session.get(url, allow_redirects=False, headers={'Referer': main_url})
        if resp.status_code != 200:
            raise stravalib.exc.Fault("Status code '{}' received when trying to "
                                      "download streams JSON for activity {}"
                                      "".format(resp.status_code, activity_id))
        sj = resp.json()
        points = zip_longest(*(sj.get(k, []) for k in streams))

        # Request lap efforts JSON, used by Strava web UI to show laps.
        # Laps will be ignored if this fails (best-effort).
        url = "{}/activities/{}/lap_efforts".format(BASE_URL, activity_id)
        resp = self._session.get(url, allow_redirects=False, headers={'Referer': main_url})
        laps_end_after = None
        if resp.status_code == 200:
            laps_end_after = [lap['end_index'] for lap in resp.json()]

        # Finally, request JSON used in Flyby feature to get exact/accurate start time.
        # Approximate start time from HTML will be used if it fails (best-effort).
        # The JSON always looks like this and we just need the first timestamp:
        #   {"stream":[{"point":{"lat":number,"lng":number},"time":integer,"elevation":number}, ...]}
        url = "{0}/flyby/stream_compare/{1}/{1}".format(NENE_URL, activity_id)
        resp = self._session.get(url, stream=True, headers={'Range': 'bytes=0-1024', 'Referer': 'https://labs.strava.com'})
        if resp.status_code == 200:
            fragment = next(resp.iter_content(chunk_size=1024))
            start = fragment.find(b'"time":')
            comma = fragment.find(b',', start)
            if start > 0 and comma > 0:
                start_time = int(fragment[start + 7: comma])
            resp.close()

        if fmt == DataFormat.TCX:
            activity_type = _tcx_sport_from_strava.get(activity_type, activity_type)
            xml = dedent("""\
                <?xml version="1.0" encoding="UTF-8"?>
                <TrainingCenterDatabase xmlns="http://www.garmin.com/xmlschemas/TrainingCenterDatabase/v2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                  <Activities>
                    <Activity Sport={}>
                      <Id>{}</Id>
                """).format(quoteattr(activity_type), _iso8601(start_time))
            if activity_title:
                xml += '      <Notes>{}</Notes>\n'.format(escape(activity_title))
            if device:
                xml += '      <Creator xsi:type="Device_t"><Name>{}</Name></Creator>\n'.format(device)

            in_lap = False
            for ii, (altitude, distance, time, latlng, heartrate, cadence) in enumerate(points):
                if not in_lap:
                    xml += '      <Lap StartTime="{}">\n        <Track>\n'.format(_iso8601(start_time + time))
                    in_lap = True
                xml += '          <Trackpoint><Time>{}</Time>'.format(_iso8601(start_time + time))
                if latlng is not None:
                    xml += '<Position><LatitudeDegrees>{}</LatitudeDegrees><LongitudeDegrees>{}</LongitudeDegrees></Position>'.format(*latlng)
                if altitude is not None:
                    xml += '<AltitudeMeters>{}</AltitudeMeters>'.format(altitude)
                if distance is not None:
                    xml += '<DistanceMeters>{}</DistanceMeters>'.format(distance)
                if heartrate is not None:
                    xml += '<HeartRateBpm><Value>{}</Value></HeartRateBpm>'.format(heartrate)
                if cadence is not None:
                    xml += '<Cadence>{}</Cadence>'.format(cadence)
                xml += '</Trackpoint>\n'
                if laps_end_after and ii == laps_end_after[0]:
                    xml += '        </Track>\n      </Lap>\n'
                    laps_end_after.pop(0)
                    in_lap = False

            if in_lap:
                xml += '        </Track>\n      </Lap>\n'
            xml += '    </Activity>\n  </Activities>\n</TrainingCenterDatabase>\n'
        elif fmt == DataFormat.GPX:
            activity_type = escape(_gpx_type_from_strava.get(activity_type, activity_type))
            xml = dedent("""\
                <?xml version="1.0" encoding="UTF-8"?>
                <gpx xmlns="http://www.topografix.com/GPX/1/1" xmlns:gpxtpx="http://www.garmin.com/xmlschemas/TrackPointExtension/v1" version="1.1" creator={}>
                  <metadata>
                    <time>{}</time>
                  </metadata>
                  <trk>
                    <type>{}</type>
                """).format(quoteattr(device), _iso8601(start_time), escape(activity_type))
            if activity_title:
                xml += '    <name>{}</name>\n'.format(escape(activity_title))

            in_lap = False
            for ii, (altitude, distance, time, latlng, heartrate, cadence) in enumerate(points):
                if not in_lap:
                    xml += '    <trkseg>\n'
                    in_lap = True
                xml += '      <trkpt'
                if latlng is not None:
                    xml += ' lat="{}" lon="{}"'.format(*latlng)
                xml += '><time>{}</time>'.format(_iso8601(start_time + time))
                if altitude is not None:
                    xml += '<ele>{}</ele>'.format(altitude)
                xml += '<extensions><gpxtpx:TrackPointExtension>'
                if distance is not None:
                    xml += '<distance>{}</distance>'.format(distance)
                if heartrate is not None:
                    xml += '<gpxtpx:hr>{}</gpxtpx:hr>'.format(heartrate)
                if cadence is not None:
                    xml += '<gpxtpx:cad>{}</gpxtpx:cad>'.format(cadence)
                xml += '</gpxtpx:TrackPointExtension></extensions></trkpt>\n'
                if laps_end_after and ii == laps_end_after[0]:
                    xml += '    </trkseg\n'
                    laps_end_after.pop(0)
                    in_lap = False

            if in_lap:
                xml += '    </trkseg>\n'
            xml += '  </trk>\n</gpx>\n'
        else:
            raise NotImplementedError("`fmt` parameter DataFormat.{} not implemented".format(fmt))

        return ActivityFile(filename=filename, content=(xml.encode(),))

    def get_activity_data(self, activity_id, fmt=DataFormat.ORIGINAL,
                          json_fmt=None):
        """
        Get a file containing the provided activity's data

        The returned data can either be the original file that was uploaded,
        a GPX file, or a TCX file.

        :param activity_id: The activity to retrieve.
        :type activity_id: int

        :param fmt: The format to request the data in
                    (defaults to DataFormat.ORIGINAL).
        :type fmt: :class:`DataFormat`

        :param json_fmt: The backup format to request in the event that the
                         `fmt` was DataFormat.ORIGINAL and the request returned
                         a JSON blob (happens for uploads from mobile apps).
                         Using `None` (default) will cause the JSON blob to be
                         returned.
        :type json_fmt: :class:`DataFormat` or None

        :return: A namedtuple with `filename` and `content` attributes:
                 - `filename` is the filename that Strava suggests for the file
                 - `contents` is an iterator that yields file contents as bytes
        :rtype: :class:`ActivityFile`
        """
        fmt = DataFormat.classify(fmt)
        url = "{}/activities/{}/export_{}".format(BASE_URL, activity_id, fmt)
        resp = self._session.get(url, stream=True, allow_redirects=False)
        if resp.status_code != 200:
            raise stravalib.exc.Fault("Status code '{}' received when trying "
                                      "to download an activity"
                                      "".format(resp.status_code))

        # In the case of downloading JSON, the Content-Type header will
        # correctly be set to 'application/json'
        if (json_fmt and fmt == DataFormat.ORIGINAL and
                resp.headers['Content-Type'].lower() == 'application/json'):
            if json_fmt == DataFormat.ORIGINAL.value:
                raise ValueError("`json_fmt` parameter cannot be DataFormat.ORIGINAL")
            return self.get_activity_data(activity_id, fmt=json_fmt)

        # Return the filename and an iterator to download the file with
        filename = self._strava_filename(resp, activity_id, fmt)
        return ActivityFile(filename=filename,
                            content=resp.iter_content(chunk_size=16384))
    @staticmethod
    def _strava_filename(resp, activity_id, fmt):
        # Get file name from request (if possible)
        content_disposition = resp.headers.get('content-disposition', "")
        filename = cgi.parse_header(content_disposition)[1].get('filename')

        # Sane default for filename
        if not filename:
            filename = str(activity_id)

        # Note that Strava always removes periods from the filename so if one
        # exists we know it's for the extension
        if "." not in filename:
            if fmt == DataFormat.ORIGINAL:
                ext = 'dat'
            else:
                ext = fmt
            filename = "{}.{}".format(filename, ext)

        return filename

    def _parse_date(self, date_str):
        if not date_str:
            return None
        if date_str.lower() == "since beginning":
            # Different from no date, but don't know exactly when it was
            return datetime.utcfromtimestamp(0).date()
        try:
            return datetime.strptime(date_str, "%b %d, %Y").date()
        except ValueError as e:
            return None

    @functools.lru_cache()
    def _get_all_bike_components(self, bike_id):
        """
        Get all components for the specified bike

        :param bike_id: The id of the bike to retreive components for
                        (must start with a "b")
        :type bike_id: str
        """
        if not bike_id.startswith('b'):
            raise ValueError("Invalid bike id (must start with 'b')")

        # chop off the leading "b"
        url = "{}/bikes/{}".format(BASE_URL, bike_id[1:])

        resp = self._session.get(url, allow_redirects=False)
        if resp.status_code != 200:
            raise stravalib.exc.Fault(
                "Failed to load bike details page (status code: {})".format(resp.status_code),
            )

        soup = BeautifulSoup(resp.text, 'html.parser')
        for table in soup.find_all('table'):
            if table.find('thead'):
                break
        else:
            raise ValueError("Bike component table not found in the HTML - layout update?")

        components = []
        for row in table.tbody.find_all('tr'):
            cells = row.find_all('td')
            text = [cell.text.strip() for cell in cells]

            # Guard against "No active components" and other messages
            if len(cells) < 7:
                continue

            # Parse distance (convert to m from mi/km)
            mul = 1609.34708 if text[5].endswith("mi") else 1000
            distance = int(float(text[5].rstrip(" kmi").replace(",", "")) * mul)

            component_id = cells[6].find('a', text="Delete")['href'].rsplit("/", 1)[-1]

            components.append({
                'id': component_id,
                'type': text[0],
                'brand': text[1],
                'model': text[2],
                'added': self._parse_date(text[3]),
                'removed': self._parse_date(text[4]),
                'distance': distance
            })
        return components

    def get_bike_components(self, bike_id, on_date=None):
        """
        Get components for the specified bike

        :param bike_id: The id of the bike to retreive components for
                        (must start with a "b")
        :type bike_id: str

        :param on_date: Only return components on the bike for this day. If
                        `None`, return all components regardless of date.
        :type on_date: None or datetime.date or datetime.datetime
        """
        components = self._get_all_bike_components(bike_id)

        # Filter by the on_date param
        if on_date:
            if isinstance(on_date, datetime):
                on_date = on_date.date()
            return [c for c in components if \
                    (c['added'] or date.min) <= on_date <= (c['removed'] or date.max)]
        else:
            return components

# Inherit parent documentation for WebClient.__init__
WebClient.__init__.__doc__ = stravalib.Client.__init__.__doc__ + \
        """
        :param email: The email of the account to log into
        :type email: str

        :param password: The password of the account to log into
        :type password: str

        :param jwt: The JWT of an existing session.
                    If not specified, email and password are required.
        :type jwt: str

        :param csrf: A dict of the form: `{<csrf-param>: <csrf-token>}`.
                     If not provided, will be scraped from the about page.
                     Can be accessed from the `.csrf` property.
        :type csrf: dict
        """
