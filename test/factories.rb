FactoryGirl.define do
  sequence :name do |n|
    "name_#{n}"
  end

  sequence :email do |n|
      "person#{n}@example.com"
  end

  sequence :hgv_identifier_string do |n|
    "oai:papyri.info:identifiers:hgv:P.Fake:#{n}"
  end

  sequence :hgv_number do |n|
    "hgv#{n}"
  end

  sequence :ddb_identifier_string do |n|
    "oai:papyri.info:identifiers:ddbdp:0001:1:#{n}"
  end

  sequence :tei_cts_identifier_string do |n|
    "perseus/greekLang/tlg0012/tlg001/edition/perseus-grc#{n}"
  end

  factory :board do |f|
    f.title { FactoryGirl.next(:name) }
    f.category 'category'
    f.identifier_classes ['DDBIdentifier']
  end

  factory :hgv_board, :parent => :board do |f|
    f.decrees { |decrees|
      [
        decrees.association(
          :percent_decree,
          :board => nil,
          :trigger => 100.0,
          :action => "accept",
          :choices => "yes no"),
        decrees.association(
          :count_decree,
          :trigger => 1.0,
          :board => nil,
          :action => "reject",
          :choices => "reject"),
        decrees.association(
          :count_decree,
          :trigger => 1.0,
          :board => nil,
          :action => "graffiti",
          :choices => "graffiti")
      ]
    }
  end
  
  factory :hgv_meta_board, :parent => :hgv_board do |f|
    f.identifier_classes ['HGVMetaIdentifier']
  end

  factory :hgv_trans_board, :parent => :hgv_board do |f|
    f.identifier_classes ['HGVTransIdentifier']
  end


  factory :user do |f|
    f.name { FactoryGirl.next(:name) }
    f.email { FactoryGirl.next(:email) }
  end

  factory :admin, :parent => :user do |f|
    f.admin true
  end

  factory :decree do |f|
    f.association :board
    f.tally_method Decree::TALLY_METHODS[:percent]
  end

  factory :percent_decree, :parent => :decree do |f|
    f.tally_method Decree::TALLY_METHODS[:percent]
  end

  factory :count_decree, :parent => :decree do |f|
    f.tally_method Decree::TALLY_METHODS[:count]
  end

  factory :emailer do |f|
    f.association :board
    f.extra_addresses 'MyText'
    f.include_document 'false'
    f.message 'MyText'
  end

  factory :event do |f|
    f.category 'commit'
  end

  factory :vote do |f|
    f.association :user
    f.association :publication
    f.choice :choice #'MyString'
  end


  factory :publication do |f|
    f.association :owner, :factory => :user
    f.creator { |pub| pub.owner }
    f.title 'MyString'
  end

  factory :HGVMetaIdentifier do |f|
    f.name { FactoryGirl.next(:hgv_identifier_string) }
    f.alternate_name { FactoryGirl.next(:hgv_number) }
  end

  factory :DDBIdentifier do |f|
    f.name { FactoryGirl.next(:ddb_identifier_string) }
  end

  factory :community do |f|
    f.name { FactoryGirl.next(:name) }
    f.friendly_name { FactoryGirl.next(:name) } 
    f.description 'description'
    f.admins Array.new
  end


  factory :comment do |f|
    f.comment :comment
    f.user_id :user_id
    f.identifier_id :identifier_id
    f.reason :reason
    f.publication_id :publicaiton_id
    
  end

  factory :TeiCTSIdentifier do |f|
    f.name { FactoryGirl.next(:tei_cts_identifier_string) }
    f.title :title
  end

end