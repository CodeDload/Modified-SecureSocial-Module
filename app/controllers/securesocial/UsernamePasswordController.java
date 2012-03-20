/**
 * Copyright 2011 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 */
package controllers.securesocial;

import notifiers.securesocial.Mails;
import play.Logger;
import play.data.validation.Email;
import play.data.validation.Equals;
import play.data.validation.Required;
import play.i18n.Messages;
import play.libs.Crypto;
import play.mvc.Controller;
import play.mvc.Router;
import securesocial.provider.*;

/**
 * The controller for the UI required by the Username Password Provider.
 */
public class UsernamePasswordController extends Controller
{
    private static final String USER_NAME = "userName";
    private static final String FORGOT_PW_USER = "forgotPwUser";
    private static final String SECURESOCIAL_USER_NAME_TAKEN = "securesocial.userNameTaken";
    private static final String SECURESOCIAL_USER_NAME_NOT_FOUND = "securesocial.userNameNotFound";
    private static final String SECURESOCIAL_ERROR_CREATING_ACCOUNT = "securesocial.errorCreatingAccount";
    private static final String SECURESOCIAL_ACCOUNT_CREATED = "securesocial.accountCreated";
    private static final String SECURESOCIAL_ACTIVATION_TITLE = "securesocial.activationTitle";
    private static final String SECURESOCIAL_SECURE_SOCIAL_NOTICE_PAGE_HTML = "securesocial/SecureSocial/noticePage.html";
    private static final String DISPLAY_NAME = "displayName";
    private static final String EMAIL = "email";
    private static final String SECURESOCIAL_INVALID_LINK = "securesocial.invalidLink";
    private static final String SECURESOCIAL_ACTIVATION_SUCCESS = "securesocial.activationSuccess";
    private static final String SECURESOCIAL_SECURE_SOCIAL_LOGIN = "securesocial.SecureSocial.login";
    private static final String SECURESOCIAL_ACTIVATE_TITLE = "securesocial.activateTitle";

    private static final String SECURESOCIAL_USER_ACCOUNT_NOT_ACTIVATED = "securesocial.userAccountNotActivated";
    private static final String SECURESOCIAL_PW_RESET_TITLE = "securesocial.pwResetTitle";
    private static final String SECURESOCIAL_PASSWORD_RESET_TITLE = "securesocial.passwordResetTitle"; // takes user arg
    private static final String SECURESOCIAL_PASSWORD_RESET_SUCCESS = "securesocial.passwordResetSuccess";
    private static final String SECURESOCIAL_ERROR_PASSWORD_RESET = "securesocial.errorPasswordReset";
    private static final String SECURESOCIAL_SECURE_SOCIAL_PW_RESET = "securesocial.SecureSocial.pwReset";
    private static final String SECURESOCIAL_SECURE_SOCIAL_PW_RESET_HTML = "securesocial/SecureSocial/pwReset.html";
    private static final String SECURESOCIAL_PASSWORD_INVALID_LINK = "securesocial.passwordInvalidLink";
    private static final String SECURESOCIAL_PASSWORD_HAS_BEEN_RESET = "securesocial.passwordHasBeenReset";
    private static final String SECURESOCIAL_PASSWORD_HAS_BEEN_UPDATED = "securesocial.passwordHasBeenUpdated";
    private static final String SECURESOCIAL_PASSWORD_UPDATED_TITLE = "securesocial.passwordUpdatedTitle";
    private static final String SECURESOCIAL_PASSWORD_NOT_RESET = "securesocial.passwordNotReset";

    /**
     * Renders the sign up page.
     */
     public static void signup() {
        render();
    }

    /**
     * Creates an account
     *
     * @param userName      The username
     * @param displayName   The user's full name
     * @param email         The email
     * @param password      The password
     * @param password2     The password verification
     */
    public static void createAccount(@Required(message = "securesocial.required") String userName,
                                     @Required String displayName,
                                     @Required @Email(message = "securesocial.invalidEmail") String email,
                                     @Required String password,
                                     @Required @Equals(message = "securesocial.passwordsMustMatch", value = "password") String password2) {
        if ( validation.hasErrors() ) {
            tryAgain(userName, displayName, email);
        }

        UserId id = new UserId();
        id.id = userName;
        id.provider = ProviderType.userpass;

        if ( UserService.find(id) != null ) {
            validation.addError(USER_NAME, Messages.get(SECURESOCIAL_USER_NAME_TAKEN));
            tryAgain(userName, displayName, email);
        }
        SocialUser user = new SocialUser();
        user.id = id;
        user.displayName = displayName;
        user.email = email;
        user.password = Crypto.passwordHash(password);
        // the user will remain inactive until the email verification is done.
        user.isEmailVerified = false;
        user.authMethod = AuthenticationMethod.USER_PASSWORD;

        try {
            UserService.save(user);
        } catch ( Throwable e ) {
            Logger.error(e, "Error while invoking UserService.save()");
            flash.error(Messages.get(SECURESOCIAL_ERROR_CREATING_ACCOUNT));
            tryAgain(userName, displayName, email);
        }

        // create an activation id
        final String uuid = UserService.createActivation(user);
        Mails.sendActivationEmail(user, uuid);
        flash.success(Messages.get(SECURESOCIAL_ACCOUNT_CREATED));
        final String title = Messages.get(SECURESOCIAL_ACTIVATION_TITLE, user.displayName);
        render(SECURESOCIAL_SECURE_SOCIAL_NOTICE_PAGE_HTML, title);
    }

    private static void tryAgain(String username, String displayName, String email) {
        flash.put(USER_NAME, username);
        flash.put(DISPLAY_NAME, displayName);
        flash.put(EMAIL, email);
        validation.keep();
        signup();
    }

    private static void tryPwResetAgain(String username) {
        flash.put(USER_NAME, username);
        flash.put(FORGOT_PW_USER, username);
        validation.keep();
        SecureSocial.login();
    }

    private static void tryPwReentryAgain(String username) {
        flash.put(USER_NAME, username);
        validation.keep();
        SecureSocial.pwReset(username);

    }

    /**
     * The action invoked from the activation email the user receives after signing up.
     *
     * @param uuid The activation id
     */
    public static void activate(String uuid) {
        try {
            if ( UserService.activate(uuid) == false ) {
                flash.error( Messages.get(SECURESOCIAL_INVALID_LINK) );
            } else {
                flash.success(Messages.get(SECURESOCIAL_ACTIVATION_SUCCESS, Router.reverse(SECURESOCIAL_SECURE_SOCIAL_LOGIN)));
            }
        } catch ( Throwable t) {
            Logger.error(t, "Error while activating account");
            flash.error(Messages.get(SECURESOCIAL_ERROR_CREATING_ACCOUNT));
        }
        final String title = Messages.get(SECURESOCIAL_ACTIVATE_TITLE);
        render(SECURESOCIAL_SECURE_SOCIAL_NOTICE_PAGE_HTML, title);
    }

    /**
     * The action invoked from the reset password link from the login page
     *
     * @param forgotPwUser The user name whose password needs to be reset
     */
    public static void resetPasswordRequest(@Required(message = "securesocial.required") String forgotPwUser) {
        if ( validation.hasErrors() ) {
            tryPwResetAgain(forgotPwUser);
        }

        UserId id = new UserId();
        id.id = forgotPwUser;
        id.provider = ProviderType.userpass;

        SocialUser user = UserService.find(id);
        if ( user == null ) {
            validation.addError(USER_NAME, Messages.get(SECURESOCIAL_USER_NAME_NOT_FOUND));
            tryPwResetAgain(forgotPwUser);
        }

        if ( user.isEmailVerified == false ) {
            validation.addError(USER_NAME, Messages.get(SECURESOCIAL_USER_ACCOUNT_NOT_ACTIVATED));
            tryPwResetAgain(forgotPwUser);
        }

        // reset password and indicate it
        user.password = "INVALID_PASSWORD";
        // the user will remain inactive until new password is set.
        user.isPasswordBeingReset = true;

        try {
            UserService.save(user);
        } catch ( Throwable e ) {
            Logger.error(e, "Error while invoking UserService.save()");
            flash.error(Messages.get(SECURESOCIAL_ERROR_CREATING_ACCOUNT));
            tryPwResetAgain(forgotPwUser);
        }

        // create an password reset id
        final String uuid = UserService.resetPasswordRequest(user);
        Mails.sendPasswordResetEmail(user, uuid);
        flash.success(Messages.get(SECURESOCIAL_PASSWORD_HAS_BEEN_RESET));
        final String title = Messages.get(SECURESOCIAL_PASSWORD_RESET_TITLE, user.displayName);
        render(SECURESOCIAL_SECURE_SOCIAL_NOTICE_PAGE_HTML, title);
    }

    /**
     * The action invoked by the link from the password reset email the user had received.
     *
     * @param uuid The unique password reset id
     */
    public static void resetPasswordVerify(String uuid) {
        String errmsg = null;
    
        try {
            String userName = UserService.resetPasswordVerify(uuid);
    
            if ( userName == null ) {
                errmsg = SECURESOCIAL_PASSWORD_INVALID_LINK;
            } else {
                // request for new password if link was correct
                flash.success(Messages.get(SECURESOCIAL_PASSWORD_RESET_SUCCESS, Router.reverse(SECURESOCIAL_SECURE_SOCIAL_PW_RESET)));
                render(SECURESOCIAL_SECURE_SOCIAL_PW_RESET_HTML, userName);
            }
        } catch ( Throwable t) {
            Logger.error(t, "Error while resetting password");
            errmsg = SECURESOCIAL_ERROR_PASSWORD_RESET;
        }

        if(errmsg != null){
            flash.error( Messages.get(errmsg) );
            final String title = Messages.get(SECURESOCIAL_PW_RESET_TITLE);
            render(SECURESOCIAL_SECURE_SOCIAL_NOTICE_PAGE_HTML, title);
        }
    }

    /**
     * The action invoked by the link from the password reset email the user had received.
     *
     * @param uuid The unique password reset id
     */
    public static void updatePassword(@Required(message = "securesocial.required") String userName,
                                     @Required String password,
                                     @Required @Equals(message = "securesocial.passwordsMustMatch", value = "password") String password2) {

        if ( validation.hasErrors() ) {
            tryPwReentryAgain(userName);
        }

        UserId id = new UserId();
        id.id = userName;
        id.provider = ProviderType.userpass;

        SocialUser user = UserService.find(id);
        if ( user == null ) {
            flash.error(Messages.get(SECURESOCIAL_USER_NAME_NOT_FOUND));
            tryPwReentryAgain(userName);
        }

        if ( user.isEmailVerified == false ) {
            flash.error(Messages.get(SECURESOCIAL_USER_ACCOUNT_NOT_ACTIVATED));
            tryPwReentryAgain(userName);
        }

        // request for password reset before initiating password change
        if ( user.isPasswordBeingReset == false ) {
            flash.error(Messages.get(SECURESOCIAL_PASSWORD_NOT_RESET));
            tryPwReentryAgain(userName);
        }

        // reset password and indicate it
        user.password = Crypto.passwordHash(password);
        user.isPasswordBeingReset = false;

        try {
            UserService.save(user);
        } catch ( Throwable e ) {
            Logger.error(e, "Error while invoking UserService.save()");
            flash.error(Messages.get(SECURESOCIAL_ERROR_CREATING_ACCOUNT));
            tryPwReentryAgain(userName);
        }

        flash.success(Messages.get(SECURESOCIAL_PASSWORD_HAS_BEEN_UPDATED, Router.reverse(SECURESOCIAL_SECURE_SOCIAL_LOGIN)));
        final String title = Messages.get(SECURESOCIAL_PASSWORD_UPDATED_TITLE, user.displayName);
        render(SECURESOCIAL_SECURE_SOCIAL_NOTICE_PAGE_HTML, title);
    }

}
