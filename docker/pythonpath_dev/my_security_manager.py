from superset.security import SupersetSecurityManager
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.utils.base import get_safe_redirect
from flask import abort, current_app, flash, g, redirect, request, session, url_for
from flask_login import login_user
from flask_appbuilder.views import expose
from flask import current_app as app


class CustomAuthDBView(AuthDBView):
    # login_template = 'appbuilder/general/security/login_db.html'
    login_template = 'superset/custom_login.html'

    @expose("/login/", methods=["GET", "POST"])
    def login(self):
        print("aaaaa: ", app.root_path, app.template_folder)
        print("aaaaa: ", app.root_path, app.template_folder)
        print("aaaaa: ", app.root_path, app.template_folder)
        print("aaaaa: ", app.root_path, app.template_folder)


        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        form = LoginForm_db()
        if form.validate_on_submit():
            print("username: ", form.username.data)
            print("password: ", form.password.data)
            next_url = get_safe_redirect(request.args.get("next", ""))
            user = self.appbuilder.sm.auth_user_db(
                form.username.data, form.password.data
            )
            if not user:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login_with(next_url))
            login_user(user, remember=False)
            return redirect(next_url)
        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )



class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
