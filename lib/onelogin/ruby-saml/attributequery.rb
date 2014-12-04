require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"

module Onelogin
  module Saml
  include REXML
    class AttributeQuery
      def create(nameId, settings, params = {})
        request_doc = create_attribute_query_xml_doc(nameId,settings)

        request = ""
        request_doc.write(request)
        request
      end

      def create_attribute_query_xml_doc(a_nameid, settings)
        uuid = "_" + UUID.new.generate
        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Create soap Envelope root element using REXML 
        request_doc = REXML::Document.new
        #request_doc.uuid = uuid
        root = request_doc.add_element "soap11:Envelope", { "xmlns:soap11" => "http://schemas.xmlsoap.org/soap/envelope/"}
        body = root.add_element "soap11:Body", { "xmlns:soap11" => "http://schemas.xmlsoap.org/soap/envelope/"}
        aq = XMLSecurity::Document.new
        aq.uuid = uuid
        query = aq.add_element "samlp:AttributeQuery", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
        query.attributes['ID'] = uuid
        query.attributes['IssueInstant'] = time
        query.attributes['Version'] = "2.0"
        query.attributes['Destination'] = "https://sosol-test.perseids.org/sosol/shib/consume"
        
        if settings.issuer != nil
          issuer = query.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion", "Format" => "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" }
          issuer.text = settings.issuer
        end
        subject = query.add_element "saml:Subject", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
        nameid = subject.add_element "saml:NameID",  { 
          "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
          "Format" => settings.name_identifier_format }
        nameid.text = a_nameid 
        private_key = settings.get_sp_key()
        cert = settings.get_sp_cert()
        aq.sign_document(private_key, cert, XMLSecurity::Document::SHA1, XMLSecurity::Document::SHA1)
        body.add(aq.root)
        request_doc
        Rails.logger.info("Now validate");
        begin 
          certificate = OpenSSL::X509::Certificate.new(cert)
          vcert = Digest::SHA1.hexdigest(certificate.to_der).upcase.scan(/../).join(":")
          test = XMLSecurity::SignedDocument.new(request_doc.to_s)
          validated = test.validate_document(vcert,true)
          Rails.logger.info("Validated AQ? #{validated} #{test.errors}")
        rescue Exception => e
          Rails.logger.info(e)
        end
      end

    end
  end
end
