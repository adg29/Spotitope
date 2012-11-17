class AddTokenToAuthentications < ActiveRecord::Migration
  def change
    add_column :authentications, :token, :string
    remove_column :authentications, :index
    remove_column :authentications, :create
    remove_column :authentications, :destroy
  end
end
