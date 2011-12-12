#Emailer contains the information needed to send emails by boards when a publication's status changes.
class Emailer < ActiveRecord::Base

belongs_to :board
has_and_belongs_to_many :users

end
