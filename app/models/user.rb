class User < ActiveRecord::Base
  has_many :authentications
  # Include default devise modules. Others available are:
  # :token_authenticatable, :encryptable, :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :omniauthable

  # Virtual attribute for authenticating by either username or email
  # This is in addition to a real persisted field like 'username'
  attr_accessor :login
  # Setup accessible (or protected) attributes for your model
  attr_accessible :login, :username, :email, :password, :password_confirmation, :remember_me

  def apply_omniauth(omniauth)
    self.email = omniauth['user_info']['email'] if email.blank?
    authentications.build(:provider => omniauth['provider'], :uid => omniauth['uid'])
  end
  
  def password_required?
    (authentications.empty? || !password.blank?) && super
  end

  def self.find_for_lastfm_oauth(access_token, signed_in_resource=nil)
    logger.debug( access_token.inspect )
    logger.debug( access_token.credentials.inspect )
    logger.debug( access_token.extra.inspect )
    logger.debug( access_token.extra.raw_info.inspect )
    data = access_token
    if user = User.where(:username => data.uid).first
      user
    else # Create a user with a stub password. 
      logger.debug( data.uid )
      User.create!(:username => data.uid, :password => Devise.friendly_token[0,20]) 
    end
  end

=begin
  Notice that Devise RegistrationsController by default calls "User.new_with_session" before building a resource. 
  This means that, if we need to copy data from session whenever a user is initialized before sign up, 
  we just need to implement new_with_session in our model. 
  Here is an example that copies the facebook email if available:
=end

  def self.new_with_session(params, session)
      logger.debug( 'session.inspect' )
      logger.debug( session.inspect )
    super.tap do |user|
      if data = session["devise.facebook_data"] && session["devise.facebook_data"]["extra"]["raw_info"]
        user.email = data["email"]
      end
      if data = session["devise.lastfm_data"] && session["devise.lastfm_data"]["uid"]
        user.username = data["uid"]
      end
    end
  end

 def self.find_for_database_authentication(warden_conditions)
   conditions = warden_conditions.dup
   login = conditions.delete(:login)
   where(conditions).where(["lower(username) = :value OR lower(email) = :value", { :value => login.strip.downcase }]).first
 end

  protected

  # Attempt to find a user by it's email. If a record is found, send new
  # password instructions to it. If not user is found, returns a new user
  # with an email not found error.
  def self.send_reset_password_instructions(attributes={})
   recoverable = find_recoverable_or_initialize_with_errors(reset_password_keys, attributes, :not_found)
   recoverable.send_reset_password_instructions if recoverable.persisted?
   recoverable
  end 

  def self.find_recoverable_or_initialize_with_errors(required_attributes, attributes, error=:invalid)
   (case_insensitive_keys || []).each { |k| attributes[k].try(:downcase!) }

   attributes = attributes.slice(*required_attributes)
   attributes.delete_if { |key, value| value.blank? }

   if attributes.size == required_attributes.size
     if attributes.has_key?(:login)
        login = attributes[:login]
        record = find_record(login)
     else  
       record = where(attributes).first
     end  
   end  

   unless record
     record = new

     required_attributes.each do |key|
       value = attributes[key]
       record.send("#{key}=", value)
       record.errors.add(key, value.present? ? error : :blank)
     end  
   end  
   record
  end

  def self.find_record(login)
   where(["username = :value OR email = :value", { :value => login }]).first
  end
end
