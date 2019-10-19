"""Base classes for request handlers"""

import json

from jupyterhub.utils import url_path_join
from tornado.httputil import url_concat
from traitlets import default

from http.client import responses
from tornado import web
from jupyterhub.services.auth import HubOAuthenticated, HubOAuth

from . import __version__ as binder_version

class OAuth(HubOAuth):

    def _login_url(self):
        login_url = self.hub_host + url_path_join(self.hub_prefix, 'authorize')
        return login_url

    def gitlab_login_url(self):
        print(self.hub_host)
        print(self.hub_prefix)
        login_url = self.hub_host + url_path_join(self.hub_prefix, 'authorize')
        return login_url

    def get_gitlab_prefix(self):
        return "oauth"


class OAuthenticated(HubOAuthenticated):
    hub_auth_class = OAuth

    def get_login_url(self):
        """Return the Hub's login URL"""
        if isinstance(self.hub_auth, OAuth):
            print("GitlabOAuth")
        login_url = self.hub_auth.login_url = self.hub_auth.gitlab_login_url()
        print(login_url)
        if isinstance(self.hub_auth, OAuth):
            # add state argument to OAuth url
            state = self.hub_auth.set_state_cookie(self, next_url=self.request.uri)
            login_url = url_concat(login_url, {'state': state})
        # app_log.debug("Redirecting to login url: %s", login_url)
        return login_url


class BaseHandler(OAuthenticated, web.RequestHandler):
    """HubAuthenticated by default allows all successfully identified users (see allow_all property)."""

    def initialize(self):
        super().initialize()
        if self.settings['auth_enabled']:
            self.hub_auth = HubOAuth.instance(config=self.settings['traitlets_config'])

    def get_current_user(self):
        if not self.settings['auth_enabled']:
            return 'anonymous'
        return super().get_current_user()

    @property
    def template_namespace(self):
        return dict(static_url=self.static_url, **self.settings.get('template_variables', {}))

    def set_default_headers(self):
        headers = self.settings.get('headers', {})
        for header, value in headers.items():
            self.set_header(header, value)
        self.set_header("access-control-allow-headers", "cache-control")

    def get_spec_from_request(self, prefix):
        """Re-extract spec from request.path.
        Get the original, raw spec, without tornado's unquoting.
        This is needed because tornado converts 'foo%2Fbar/ref' to 'foo/bar/ref'.
        """
        idx = self.request.path.index(prefix)
        spec = self.request.path[idx + len(prefix) + 1:]
        return spec

    def get_provider(self, provider_prefix, spec, repo_url):
        """Construct a provider object"""
        providers = self.settings['repo_providers']
        if provider_prefix not in providers:
            raise web.HTTPError(404, "No provider found for prefix %s" % provider_prefix)

        return providers[provider_prefix](
            config=self.settings['traitlets_config'], spec=spec, repo_url=repo_url)

    def render_template(self, name, **extra_ns):
        """Render an HTML page"""
        ns = {}
        ns.update(self.template_namespace)
        ns.update(extra_ns)
        template = self.settings['jinja2_env'].get_template(name)
        html = template.render(**ns)
        self.write(html)

    def extract_message(self, exc_info):
        """Return error message from exc_info"""
        exception = exc_info[1]
        # get the custom message, if defined
        try:
            return exception.log_message % exception.args
        except Exception:
            return ''

    def write_error(self, status_code, **kwargs):
        exc_info = kwargs.get('exc_info')
        message = ''
        status_message = responses.get(status_code, 'Unknown HTTP Error')
        if exc_info:
            message = self.extract_message(exc_info)

        self.render_template(
            'error.html',
            status_code=status_code,
            status_message=status_message,
            message=message,
        )

    def options(self, *args, **kwargs):
        pass


class Custom404(BaseHandler):
    """Raise a 404 error, rendering the error.html template"""

    def prepare(self):
        raise web.HTTPError(404)


class AboutHandler(BaseHandler):
    """Serve the about page"""
    async def get(self):
        self.render_template(
            "about.html",
            base_url=self.settings['base_url'],
            submit=False,
            binder_version=binder_version,
            message=self.settings['about_message'],
            google_analytics_code=self.settings['google_analytics_code'],
            google_analytics_domain=self.settings['google_analytics_domain'],
            extra_footer_scripts=self.settings['extra_footer_scripts'],
        )


class VersionHandler(BaseHandler):
    """Serve information about versions running"""
    async def get(self):
        self.set_header("Content-type", "application/json")
        self.write(json.dumps(
            {
                "builder": self.settings['build_image'],
                "binderhub": binder_version,
                }
        ))
