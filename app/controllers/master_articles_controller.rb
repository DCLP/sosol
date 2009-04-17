class MasterArticlesController < ApplicationController
  
  layout "site"
  
  def ask_to_add_article
  	@master_article = MasterArticle.find(params[:id])
  end
  def add_article
  	@master_article = MasterArticle.find(params[:id])
  	
  	tmMeta = params[:tmMeta]
  	if tmMeta != nil && tmMeta.strip != ""
  	#try to open a meta with tm number
  		@master_article.add_meta_article(tmMeta)
  	elsif params[:doMeta] == "doMeta"
  	#create a new meta  
  		@master_article.add_meta_article(nil)
  	end
  	
  	tmTranscription = params[:tmTranscription]
  	if tmTranscription != nil && tmTranscription.strip != ""
  	#try to open a Transcription with tm number
  		@master_article.add_transcription_article(tmTranscription)
  	elsif params[:doTranscription] == "doTranscription"
  	#create a new Transcription
  		@master_article.add_transcription_article(nil)
  	end
  	
  	tmTranslation = params[:tmTranslation]
  	if tmTranslation != nil && tmTranslation.strip != ""
  	#try to open a Translation with tm number
  		@master_article.add_translation_article(tmTranslation)
  	elsif params[:doTranslation] == "doTranslation"
  	#create a new Translation
  		@master_article.add_translation_article(nil)
  	end
  	
  	@master_article.save
  	
  	redirect_to @master_article
  end
  
  def show_deletes
  	@master_article = MasterArticle.find(params[:id])
  end
  
  # GET /master_articles
  # GET /master_articles.xml
  def index
    @master_articles = MasterArticle.find(:all)

    respond_to do |format|
      format.html # index.html.erb
      format.xml  { render :xml => @master_articles }
    end
  end

  # GET /master_articles/1
  # GET /master_articles/1.xml
  def show
    @master_article = MasterArticle.find(params[:id])

    respond_to do |format|
      format.html # show.html.erb
      format.xml  { render :xml => @master_article }
    end
  end

  # GET /master_articles/new
  # GET /master_articles/new.xml
  def new
    @master_article = MasterArticle.new
  

    respond_to do |format|
      format.html # new.html.erb
      format.xml  { render :xml => @master_article }
    end
  end

  # GET /master_articles/1/edit
  def edit
    @master_article = MasterArticle.find(params[:id])
    
	#make it the current master
	set_current_master_article(@master_article.id)
	redirect_to :controller => 'user', :action => 'dashboard'
  end

  # POST /master_articles
  # POST /master_articles.xml
  def create
  	flash[:notice] = ""
    @master_article = MasterArticle.new(params[:master_article])
    @master_article.user_id = @current_user.id
    @master_article.save
    #TODO add warning if not saved
     #is there a way to delay saving? we need the master_article id now

		#how are they starting the article
		
		#------TM----- 
		if params[:tm_number]
		
		#just by the tm number
			if @master_article.title.strip == ""
				#give the title the tm number
				@master_article.title = params[:tm_number]
			end
			begin
				@master_article.add_meta_article(params[:tm_number])
			rescue
				@master_article.add_meta_article(nil)
				flash[:notice] += "Existing Meta not found."
			end
			
			begin
				@master_article.add_transcription_article(params[:tm_number])
			rescue
				@master_article.add_transcription_article(nil)
				flash[:notice] += "Existing text not found."
			end
			
			begin
				@master_article.add_translation_article(params[:tm_number])
			rescue
				@master_article.add_translation_article(nil)
				flash[:notice] += "Existing translation not found."
			end
		#=====tm====
		else


	#make it the current master
	#set_current_master_article(@master_article.id)

       #for now hard code the types
    if params[:doMeta]
				@meta_article = Article.new
				@meta_article.category = "Meta"
				@meta_article.master_article_id = @master_article.id
				@meta_article.user_id = @current_user.id
				@meta_article.content = "<xml>none</xml>"
				@meta_article.status = "new"
				@meta_article.save
				#TODO add warning if not saved
				
				@meta = Meta.new()
				@meta.article_id = @meta_article.id
				@meta.user_id = @current_user.id		               
				@meta.save
				#TODO add warning if not saved
        
        board = Board.find_by_category("Meta")
        if board != nil
        	board.articles << @meta_article
        	board.save
        	#TODO add warning if not saved
        	@meta_article.board_id = board.id        
        end
        
        @meta_article.meta_id = @meta.id
        @meta_article.save
        #TODO add warning if not saved
        
    end
        
        
    if params[:doTranscription]
				@script_article = Article.new
				@script_article.category = "Transcription"
				@script_article.master_article_id = @master_article.id
				@script_article.user_id = @current_user.id
				@script_article.content = "<xml>none</xml>"
				@script_article.status = "new"
				@script_article.save
				#TODO add warning if not saved
				
				@script = Transcription.new()
				@script.article_id = @script_article.id
        @script.user_id = @current_user.id
        @script.save
        #TODO add warning if not saved
        
        board = Board.find_by_category("Transcription")
        if board != nil
        	board.articles << @script_article
        	board.save
        	#TODO add warning if not saved
        	@script_article.board_id = board.id        
        end        
        
        @script_article.transcription_id = @script.id
        @script_article.save
        #TODO add warning if not saved
    end
     
     
    if params[:doTranslation]
				@trans_article = Article.new
				@trans_article.category = "Translation"
				@trans_article.master_article_id = @master_article.id
				@trans_article.user_id = @current_user.id
				@trans_article.content = "<xml>none</xml>"
				@trans_article.status = "new"
				@trans_article.save
				#TODO add warning if not saved
				
				@translation = Translation.new()
				@translation.xml_to_translations_ok = true
    		@translation.translations_to_xml_ok = true
				@translation.article_id = @trans_article.id
        @translation.user_id = @current_user.id
        @translation.save
        #TODO add warning if not saved
        
        board = Board.find_by_category("Translation")
        if board != nil
        	board.articles << @trans_article
        	board.save
        	#TODO add warning if not saved
        	@trans_article.board_id = board.id        
        end        
        
        @trans_article.translation_id = @translation.id
        @trans_article.save
        #TODO add warning if not saved
    end
       
    end
  #TODO add warnings, backouts for above failures etc..
    respond_to do |format|
      if @master_article.save
        #flash[:notice] += 'MasterArticle was successfully created.'
        format.html { redirect_to(@master_article) }
        format.xml  { render :xml => @master_article, :status => :created, :location => @master_article }
      else
        format.html { render :action => "new" }
        format.xml  { render :xml => @master_article.errors, :status => :unprocessable_entity }
      end
    end
  end

  # PUT /master_articles/1
  # PUT /master_articles/1.xml
  def update
    @master_article = MasterArticle.find(params[:id])

    respond_to do |format|
      if @master_article.update_attributes(params[:master_article])
        flash[:notice] = 'MasterArticle was successfully updated.'
        format.html { redirect_to(@master_article) }
        format.xml  { head :ok }
      else
        format.html { render :action => "edit" }
        format.xml  { render :xml => @master_article.errors, :status => :unprocessable_entity }
      end
    end
  end

  # DELETE /master_articles/1
  # DELETE /master_articles/1.xml
  def destroy
    @master_article = MasterArticle.find(params[:id])
    
    @master_article.articles.destroy_all
    @master_article.destroy
    

    respond_to do |format|
      format.html { redirect_to dashboard_url }
      format.xml  { head :ok }
    end
  end
end
