class PagesController < HighVoltage::PagesController
  before_filter :authenticate
  layout :layout_for_page

  def authenticate
  	logger.debug('authenticate')
  end

  protected
    def layout_for_page
      case params[:id]
      when 'home'
        'home'
      else
        'application'
      end
    end
end