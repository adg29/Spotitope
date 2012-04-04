class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def lastfm 
    # You need to implement the method below in your model
    logger.debug('request.env["omniauth.auth"]')
    logger.debug(request.env["omniauth.auth"])
    @user = User.find_for_lastfm_oauth(request.env["omniauth.auth"], current_user)

    if @user.persisted?
      flash[:notice] = I18n.t "devise.omniauth_callbacks.success", :kind => "Lastfm"
      sign_in_and_redirect @user, :event => :authentication
    else
      session["devise.lastfm_data"] = request.env["omniauth.auth"]
      redirect_to new_user_registration_url
    end
  end
end
