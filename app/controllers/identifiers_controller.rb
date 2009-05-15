class IdentifiersController < ApplicationController
  # def method_missing(method_name, *args)
  #   identifier = Identifier.find(params[:id])
  #   redirect_to :controller => identifier.class.to_s.pluralize.underscore, :action => method_name
  # end
  
  # GET /publications/1/xxx_identifiers/1/editxml
  def editxml
    find_identifier
    @identifier[:xml_content] = @identifier.xml_content
    render :template => 'identifiers/editxml'
  end
  
  # GET /publications/1/xxx_identifiers/1/history
  def history
    find_identifier
    @identifier.get_commits
    render :template => 'identifiers/history'
  end
  
  # PUT /publications/1/xxx_identifiers/1/updatexml
  def updatexml
    find_identifier
    # strip carriage returns
    xml_content = params[:ddb_identifier][:xml_content].gsub(/\r\n?/, "\n")
    @identifier.set_xml_content(xml_content,
                                params[:comment])
    flash[:notice] = "File updated."
    redirect_to polymorphic_path([@identifier.publication, @identifier],
                                 :action => :editxml) and return
  end
end