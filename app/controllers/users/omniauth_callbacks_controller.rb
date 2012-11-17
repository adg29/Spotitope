class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  before_filter { @omniauth_hash = env["omniauth.auth"] }

  # This method is responsible to create a registration_hash given an
  # omniauth_hash
  # schema: https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
  def self.build_registration_hash(omniauth_hash={})
    logger.debug('self.build_registration_hash')
    logger.debug(omniauth_hash)
    logger.debug(@omniauth_hash)
    if (omniauth_hash["provider"].downcase.eql?("facebook"))
      logger.debug('facebook on omniauth hash provider downcase')
      provider  = "facebook"
      # catch any excpetions thrown by code just to make sure we can continue even if parts of the omnia_has are missing
      begin
        first_name = omniauth_hash['user_info']['first_name']
        last_name  = omniauth_hash['user_info']['last_name']
        sex        = omniauth_hash.fetch('extra', {}).fetch('user_hash',{})['gender']
        birthday   = Date.strptime(omniauth_hash.fetch('extra', {}).fetch('user_hash', {})['birthday'],'%m/%d/%Y') if omniauth_hash.fetch('extra', {}).fetch('user_hash', {})['birthday']
        if omniauth_hash.fetch('extra', {}).fetch('user_hash', {})['timezone']
          utc_offset_in_hours = (omniauth_hash.fetch('extra', {}).fetch('user_hash', {})['timezone']).to_i 
          time_zone = (ActiveSupport::TimeZone[utc_offset_in_hours]).name
        else
          time_zone = nil
        end
        locale    = omniauth_hash.fetch('extra', {}).fetch('user_hash', {})['locale'] 
        home_town = omniauth_hash.fetch('extra', {}).fetch('user_hash', {}).fetch('location', {})['name']
        if omniauth_hash.fetch('user_info', {})['image']
          photo_url = (omniauth_hash.fetch('user_info', {})['image']).gsub("=square","=large")   #http://graph.facebook.com/531564247/picture?type=square
        else
          photo_url = nil
        end
      rescue => ex
        logger.error("Error while parsing facebook auth hash: #{ex.class}: #{ex.message}")
        sex       = nil
        birthday  = nil
        time_zone = nil
        locale    = nil
        home_town = nil
        photo_url = nil  
      end
    elsif omniauth_hash['uid'].downcase.include?("google.com")
      provider  = "google"
      if omniauth_hash['user_info']['first_name'] and omniauth_hash['user_info']['last_name']
        first_name = omniauth_hash['user_info']['first_name'] 
        last_name  = omniauth_hash['user_info']['last_name']
      elsif omniauth_hash['user_info']['name'] 
        first_name  = omniauth_hash['user_info']['name'].split(' ')[0]
        last_name  = omniauth_hash['user_info']['name'].split(' ')[1]
      else
        first_name = nil
        last_name  = nil
      end
      sex       = nil
      birthday  = nil
      time_zone = nil
      locale    = nil
      home_town = nil
      photo_url = nil
    elsif omniauth_hash['uid'].downcase.include?("yahoo.com")
      provider = "yahoo"
      if omniauth_hash['user_info']['first_name'] and omniauth_hash['user_info']['last_name']
        first_name = omniauth_hash['user_info']['first_name'] 
        last_name  = omniauth_hash['user_info']['last_name']
      elsif omniauth_hash['user_info']['name'] 
        first_name  = omniauth_hash['user_info']['name'].split(' ')[0]
        last_name  = omniauth_hash['user_info']['name'].split(' ')[1]
      else
        first_name = nil
        last_name  = nil
      end
      sex       = nil
      birthday  = nil
      time_zone = nil
      locale    = nil
      home_town = nil
      photo_url = nil
    elsif omniauth_hash['uid'].downcase.include?("aol.com")
      if omniauth_hash['user_info']['first_name'] and omniauth_hash['user_info']['last_name']
        first_name = omniauth_hash['user_info']['first_name'] 
        last_name  = omniauth_hash['user_info']['last_name']
      elsif omniauth_hash['user_info']['name'] 
        first_name  = omniauth_hash['user_info']['name'].split(' ')[0]
        last_name  = omniauth_hash['user_info']['name'].split(' ')[1]
      else
        first_name = nil
        last_name  = nil
      end
      provider = "aol"
      sex       = nil
      birthday  = nil
      time_zone = nil
      locale    = nil
      home_town = nil
      photo_url = nil     
    else
      provider = "open_id"
      if omniauth_hash['user_info']['first_name'] and omniauth_hash['user_info']['last_name']
        first_name = omniauth_hash['user_info']['first_name'] 
        last_name  = omniauth_hash['user_info']['last_name']
      elsif omniauth_hash['user_info']['name'] 
        first_name  = omniauth_hash['user_info']['name'].split(' ')[0]
        last_name  = omniauth_hash['user_info']['name'].split(' ')[1]
      else
        first_name = nil
        last_name  = nil
      end
      sex       = nil
      birthday  = nil
      time_zone = nil
      locale    = nil
      home_town = nil
      photo_url = nil
    end

    logger.debug('creating HASHHHHH')
    logger.debug(omniauth_hash.inspect)
   h = {
      :provider   => provider,
      :email      => omniauth_hash['info']['email'],
      :profile_attributes => {
         :first_name => first_name ,
         :last_name  => last_name,
         :avatar_url  => photo_url,
         :sex        => sex,
         :birthday   => birthday,
         :time_zone  => time_zone,
         :locale     => locale,
         :location  => home_town
      }
    }
  end

  def process_callback

    # The registration hash isolates the rest of the code from learning all the different structures 
    # of the omnia_hash
    registration_hash = Users::OmniauthCallbacksController.build_registration_hash(@omniauth_hash)
    logger.debug(registration_hash.to_yaml)

    # Set the @user to nil 
    @user = nil 

    # Find if an authentication token for this provider and user id already exists
    authentication = Authentication.find_by_provider_and_uid(@omniauth_hash['provider'], @omniauth_hash['uid'])
    if authentication     # We found an authentication
      if user_signed_in? && (authentication.user.id != current_user.id)
        flash[:error] = I18n.t "controllers.omniauth_callbacks.process_callback.error.account_already_taken", 
        :provider => registration_hash[:provider].capitalize, 
        :account => registration_hash[:email]
        redirect_to edit_user_account_path(current_user)
        return
      end
    else
      # We could not find the authentication than create one
      authentication = Authentication.new(:provider => @omniauth_hash['provider'], :uid => @omniauth_hash['uid'])
      if user_signed_in?   
        authentication.user = current_user
      else
        registration_hash[:skip_confirmation] = true
        authentication.user = User.find_by_email(registration_hash[:email]) || User.create_user(registration_hash)
      end
    end

    @user = authentication.user
    # save the authentication 
    authentication.token = @omniauth_hash
    authentication.provider = registration_hash[:provider]
    authentication.user_id = registration_hash[:email]

    if !authentication.save
      logger.error(authentication.errors)
    end

    # If a user is signed in then he is trying to link a new account
    if user_signed_in?
      if authentication.persisted? # This was a linking operation so send back the user to the account edit page  
        flash[:success] = I18n.t "controllers.omniauth_callbacks.process_callback.success.link_account", 
                                :provider => registration_hash[:provider].capitalize, 
                                :account => registration_hash[:email]
      else
        flash[:error] = I18n.t "controllers.omniauth_callbacks.process_callback.error.link_account", 
                               :provider => registration_hash[:provider].capitalize, 
                               :account => registration_hash[:email],
                               :errors =>authentication.errors
      end  
      redirect_to edit_user_account_path(current_user)
    else
      # This was a sign in operation so sign in the user and redirect it to his home page
      if @user.persisted? && authentication.persisted?
        flash[:success] = I18n.t "controllers.omniauth_callbacks.process_callback.success.sign_in", 
        :provider => registration_hash[:provider].capitalize, 
        :account => registration_hash[:email]
        sign_in_and_redirect(:user,@user)
      else
        session['registration_hash'] = registration_hash
        flash[:error] = I18n.t "controllers.omniauth_callbacks.process_callback.error.sign_in", 
        :provider => registration_hash[:provider].capitalize, 
        :account => registration_hash[:email]

        redirect_to new_registration_users_url

      end
    end
  end

  def facebook
    process_callback  
  end

  def gmail
    process_callback  
  end
end