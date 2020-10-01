import cgi
from collections import namedtuple
from datetime import date, datetime
import functools
import enum
import uuid

from bs4 import BeautifulSoup
import requests
import stravalib
from stravalib.attributes import Attribute, TimestampAttribute, TimeIntervalAttribute
from stravalib.model import Activity, BaseEntity


__all__ = ["WebClient", "ScrapingClient", "FrameType", "DataFormat", "ActivityFile", "ScrapedActivity"]


BASE_URL = "https://www.strava.com"

# Used for filtering when scraping the activity list
ACTIVITY_WORKOUT_TYPES = {
    "Ride": {None: 10, "Race": 11, "Workout": 12},
    "Run": {None: 0, "Race": 1, "Long Run": 2, "Workout": 3}
}

ActivityFile = namedtuple("ActivityFile", ("filename", "content"))


class ScrapedActivity(BaseEntity):
    """
    Represents an Activity (ride, run, etc.) that was scraped from the website

    The attributes are compatible with stravalib.model.Activity where possible
    (some are missing)
    """

    id = Attribute(int)
    name = Attribute(str)
    description = Attribute(str)
    type = Attribute(str)
    workout_type = Attribute(str)

    start_date = TimestampAttribute()
    distance = Attribute(float)
    moving_time = TimeIntervalAttribute()
    elapsed_time = TimeIntervalAttribute()
    total_elevation_gain = Attribute(float)
    suffer_score = Attribute(int)
    calories = Attribute(float)
    gear_id = Attribute(str)

    has_latlng = Attribute(bool)

    trainer = Attribute(bool)
    commute = Attribute(bool)
    private = Attribute(bool)
    flagged = Attribute(bool)

    def from_dict(self, d):
        bike_id = d.get("bike_id")
        shoes_id = d.get("athlete_gear_id")
        if bike_id:
            d["gear_id"] = "b{}".format(bike_id)
        elif shoes_id:
            d["gear_id"] = "g{}".format(shoes_id)

        d["start_date"] = d.pop("start_time")
        d["distance"] = d.pop("distance_raw")
        d["moving_time"] = d.pop("moving_time_raw")
        d["elapsed_time"] = d.pop("elapsed_time_raw")
        d["total_elevation_gain"] = d.pop("elevation_gain_raw")

        wt = d.pop("workout_type")
        if d["type"] in ACTIVITY_WORKOUT_TYPES:
            for k, v in ACTIVITY_WORKOUT_TYPES[d["type"]].items():
                if wt == v:
                    d["workout_type"] = k
                    break

        return super().from_dict(d)


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


class ScrapingClient:
    """
    A client that uses web scraping to interface with Strava.

    Can be used as a mixin to add the extra methods to the main stravalib.Client
    """

    def __init__(self, *args, email, password, **kwargs):
        if not email or not password:
            raise ValueError("'email' and 'password' kwargs are required")

        self._csrf = {}
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
        self._login(email, password)

        super().__init__(*args, **kwargs)

    def _login(self, email, password):
        """Log into the website"""

        login_url = "{}/login".format(BASE_URL)
        session_url = "{}/session".format(BASE_URL)

        # Get CSRF token
        login_html = self._session.get(login_url).text
        soup = BeautifulSoup(login_html, 'html5lib')

        try:
            head = soup.head
            csrf_param = head.find('meta', attrs={"name": "csrf-param"}).attrs['content']
            csrf_token = head.find('meta', attrs={"name": "csrf-token"}).attrs['content']
        except (AttributeError, KeyError) as e:
            # "AttributeError: 'NoneType' object has no attr..." when failing
            # to find the tags.
            raise stravalib.exc.LoginFailed("Couldn't find CSRF token") from e

        # Save csrf token to use throughout the session
        self._csrf = {csrf_param: csrf_token}
        post_info = {
            "email": email,
            "password": password,
            "remember_me": "on",
            **self._csrf
        }
        resp = self._session.post(session_url, allow_redirects=False, data=post_info)
        if not resp.is_redirect or resp.next.url == login_url:
            raise stravalib.exc.LoginFailed("Couldn't log in to website, check creds")

    def scrape_activites(self, keywords=None, activity_type=None, workout_type=None,
                         commute=False, is_private=False, indoor=False, gear_id=None):
        """A scraping-based alternative to stravalib.Client.get_activities()

        Note that when using multiple parameters they are treated as AND, not OR

        :param keywords: Text to search for
        :param activity_type: The type of the activity. See stravalib.model:Activity.TYPES
        :param workout_type: The type of workout ("Race", "Workout", etc)
        :param commute: Only return activities marked as commutes
        :param is_private: Only return private activities
        :param indoor: Only return indoor/trainer activities
        :param gear_id: Only return activities using this gear

        :yield: ScrapedActivity objects
        """

        if activity_type is not None and activity_type not in Activity.TYPES:
            raise ValueError(
                "Invalid activity type. Must be one of: {}".format(",".join(Activity.TYPES))
            )

        if activity_type in ACTIVITY_WORKOUT_TYPES:
            workout_type = ACTIVITY_WORKOUT_TYPES[activity_type].get(workout_type)
            if workout_type is None:
                raise ValueError(
                    "Invalid workout type for a {}. Must be one of: {}".format(
                        activity_type,
                        ", ".join(ACTIVITY_WORKOUT_TYPES[activity_type].keys())
                    )
                )
        elif workout_type is not None or gear_id is not None:
            raise ValueError(
                "Can only filter using workout type of gear when activity type is one of: {}".format(
                    ", ".join(ACTIVITY_WORKOUT_TYPES.keys())
                )
            )

        page = 1
        per_page = 20
        search_session_id = uuid.uuid4()

        conv_bool = lambda x: "" if not x else "true"

        while True:
            resp = self._session.get(
                "{}/athlete/training_activities".format(BASE_URL),
                headers= {
                    "Accept": "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript",
                    #"X-CSRF-Token": next(iter(self._csrf.values())),
                    "X-Requested-With": "XMLHttpRequest",
                },
                params={
                    "search_session_id": search_session_id,
                    "page": page,
                    "per_page": per_page,
                    "keywords": keywords,
                    "new_activity_only": "false",
                    "activity_type": activity_type or "",
                    "commute": conv_bool(commute),
                    "private_activities": conv_bool(is_private),
                    "trainer": conv_bool(indoor),
                    "gear": gear_id or "",
                }
            )
            if resp.status_code != 200:
                raise stravalib.exc.Fault(
                    "Failed to list activities (status code {})".format(resp.status_code)
                )
            try:
                data = resp.json()["models"]
            except (ValueError, TypeError, KeyError) as e:
                raise stravalib.exc.Fault(
                    "Invalid JSON response from Strava"
                ) from e

            for activity in data:
                yield ScrapedActivity(**activity)

            # No results = stop requesting pages
            if not data:
                break

    def delete_activity(self, activity_id):
        """
        Deletes the specified activity.

        :param activity_id: The activity to delete.
        :type activity_id: int
        """
        url = "{}/activities/{}".format(BASE_URL, activity_id)
        resp = self._session.post(url, allow_redirects=False,
                                  data={"_method": "delete", **self._csrf})

        if not resp.is_redirect or resp.next.url != "{}/athlete/training".format(BASE_URL):
            raise stravalib.exc.Fault(
                "Failed to delete activity (status code: {})".format(resp.status_code),
            )

    def get_activity_data(self, activity_id, fmt=DataFormat.ORIGINAL, json_fmt=None):
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

        # Return the filename and an iterator to download the file with
        return ActivityFile(filename=filename,
                            content=resp.iter_content(chunk_size=16384))

    @staticmethod
    def _parse_date(date_str):
        if not date_str:
            return None
        if date_str.lower() == "since beginning":
            # Different from no date, but don't know exactly when it was
            return datetime.utcfromtimestamp(0).date()
        try:
            return datetime.strptime(date_str, "%b %d, %Y").date()
        except ValueError:
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

        soup = BeautifulSoup(resp.text, 'html5lib')
        table = None
        for t in soup.find_all('table'):
            if t.find('thead'):
                table = t
                break

        if not table:
            raise ValueError("Bike component table not found in the HTML - layout update?")

        components = []
        for row in table.tbody.find_all('tr'):
            cells = row.find_all('td')
            text = [cell.text.strip() for cell in cells]

            # Guard against "No active components" and other messages
            if len(cells) < 7:
                continue

            # Parse and convert from km to m
            # TODO: Will this ever be anything but km?
            distance = int(float(text[5].strip(" km").replace(',', '')) * 1000)

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


# Mix in the ScrapingClient to inherit all its methods
class WebClient(ScrapingClient, stravalib.Client):
    """
    An extension to the stravalib Client that fills in some of the gaps in
    the official API using web scraping.

    Requires a username and password
    """


# Inherit parent documentation for WebClient.__init__
WebClient.__init__.__doc__ = stravalib.Client.__init__.__doc__ + \
        """
        :param email: The email of the account to log into
        :type email: str

        :param password: The password of the account to log into
        :type password: str
        """
