class RepositoriesController < ApplicationController
  #layout 'site'
  before_filter :authorize
  
  before_filter :find_repository

  def index
    redirect_to :action => 'tree'
  end
  
  def tree
    tree = @repo.tree
    
    @contents = []
    tree.contents.each do |content|
      @contents << content
    end
  end
  
  def blob
    
  end
  
  protected
  
    def find_repository
      @repo = @current_user.repository.repo
    end
end
