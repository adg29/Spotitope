class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  
  def action_missing(provider)
    logger.debug('missing')
    logger.debug( provider )
    logger.debug( User.omniauth_providers )
    logger.debug( provider.parameterize.underscore.to_sym )
    logger.debug( !User.omniauth_providers.index(provider.parameterize.underscore.to_sym).nil? )
    omniauth_providers = User.omniauth_providers.collect {|p| p.to_s }
    if !omniauth_providers.index(provider).nil?
    logger.debug('omniauth providers not available')
      omniauth = request.env["omniauth.auth"]
      #omniauth = env["omniauth.auth"]
    
      if current_user #or User.find_by_email(auth.recursive_find_by_key("email"))
        current_user.authentications.find_or_create_by_provider_and_uid(omniauth['provider'], omniauth['uid'])
         flash[:notice] = "Authentication successful"
         redirect_to edit_user_registration_path
      else
        authentication = Authentication.where(:provider => omniauth['provider'], :uid => omniauth['uid']).first
        logger.debug("@@@@AUTHEN@@@@#{authentication}" )
        if authentication
          flash[:notice] = I18n.t "devise.omniauth_callbacks.success", :kind => omniauth['provider']
          sign_in_and_redirect(:user, authentication.user)
        else
          logger.debug("@@@MANIVANNAN@@")
          #create a new user
          if omniauth.recursive_find_by_key("email").blank?
            logger.debug('user new')
            user = User.new
          else
            logger.debug('user find or init')
            user = User.find_or_initialize_by(:email => omniauth.recursive_find_by_key("email"))
          end
          
          user.apply_omniauth(omniauth)
          #user.confirm! #unless user.email.blank?

          if user.save
            flash[:notice] = I18n.t "devise.omniauth_callbacks.success", :kind => omniauth['provider'] 
            logger.debug('user save')
            sign_in_and_redirect(:user, user)
          else
            session[:omniauth] = omniauth.except('extra')
            logger.debug('new user reg')
            redirect_to new_user_registration_url
          end
        end
      end
    end
  end
end
