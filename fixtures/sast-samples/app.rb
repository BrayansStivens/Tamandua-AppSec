class UsersController < ApplicationController
  def show
    User.where("name = '#{params[:name]}'")
    system("ping #{params[:host]}")
    Marshal.load(params[:blob])
    redirect_to params[:next]
    params.permit!
    render html: params[:body].html_safe
  end
end
