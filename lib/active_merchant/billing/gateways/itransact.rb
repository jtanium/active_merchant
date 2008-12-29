module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # iTransact, Inc. is an authorized reseller of the PaymentClearing gateway. If your merchant service provider uses PaymentClearing.com to process payments, you can use this module.
    #
    #
    # Please note, the username and API Access Key are not what you use to log into the Merchant Control Panel.
    #
    # ==== How to get your GatewayID and API Access Key
    #
    # 1. If you don't already have a Gateway Account, go to http://www.itransact.com/merchant/test.html to sign up.
    # 2. Go to http://support.paymentclearing.com and login or register, if necessary.
    # 3. Click on "Submit a Ticket."
    # 4. Select "Merchant Support" as the department and click "Next"
    # 5. Enter *both* your company name and GatewayID. Put "API Access Key" in the subject.  In the body, you can request a username, but it may already be in use.
    #
    # ==== Initialization
    #
    # Once you have the username, API Access Key, and your GatewayId, you're ready
    # to begin.  You initialize the Gateway like so:
    #
    #   gateway = ActiveMerchant::Billing::ItransactGateway.new(
    #     :login => "#{THE_USERNAME}",
    #     :password => "#{THE_API_ACCESS_KEY}",
    #     :gateway_id => "#{THE_GATEWAY_ID}"
    #   )
    #
    # ==== Important Notes
    # 1. Recurring is not implemented
    # 1. CreditTransactions are not implemented (these are credits not related to a previously run transaction).
    # 1. TransactionStatus is not implemented
    #
    class ItransactGateway < Gateway
      URL = 'https://secure.paymentclearing.com/cgi-bin/rc/xmltrans2.cgi'

      # The countries the gateway supports merchants from as 2 digit ISO country codes
      self.supported_countries = ['US']

      # The card types supported by the payment gateway
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]

      # The homepage URL of the gateway
      self.homepage_url = 'http://www.itransact.com/'

      # The name of the gateway
      self.display_name = 'iTransact'

      #
      # Creates a new instance of the iTransact Gateway.
      #
      # ==== Parameters
      # * <tt>options</tt> - A Hash of options
      # 
      # ==== Options Hash
      # * <tt>:login</tt> - A String containing your PaymentClearing assigned API Access Username
      # * <tt>:password</tt> - A String containing your PaymentClearing assigned API Access Key
      # * <tt>:gateway_id</tt> - A String containing your PaymentClearing assigned GatewayID
      # * <tt>:test_mode</tt> - <tt>true</tt> or <tt>false</tt>. Run *all* transactions with the 'TestMode' element set to 'TRUE'.
      #
      def initialize(options = {})
        requires!(options, :login, :password, :gateway_id)
        @options = options
        super
      end

      # Performs an authorize transaction.  In PaymentClearing's documentation
      # this is known as a "PreAuth" transaction.
      #
      # ==== Parameters
      # * <tt>money</tt> - The amount to be captured. Should be an Integer amount in cents.
      # * <tt>creditcard</tt> - The CreditCard details for the transaction
      # * <tt>options</tt> - A Hash of options
      #
      # ==== Options Hash
      # The standard options apply here (:order_id, :ip, :customer, :invoice, :merchant, :description, :email, :currency, :address, :billing_address, :shipping_address), as well as:
      # * <tt>:order_items</tt> - An Array of Hash objects with the keys <tt>:description</tt>, <tt>:cost</tt> (in cents!), and <tt>:quantity</tt>.  If this is provided, <tt>:description</tt> and <tt>money</tt> will be ignored.
      # * <tt>:vendor_data</tt> - An Array of Hash objects with the keys being the name of the VendorData element and value being the value.
      # * <tt>:send_customer_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendCustomerEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:send_merchant_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendMerchantEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:email_text</tt> - An Array of (up to ten (10)) String objects to be included in emails
      # * <tt>:test_mode</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'TestMode' element set to 'TRUE' or 'FALSE'.
      #
      # ==== Examples
      #  response = gateway.authorize(1000, creditcard,
      #    :order_id => '1212', :address => {...}, :email => 'test@test.com',
      #    :order_items => [
      #      {:description => 'Line Item 1', :cost => '8.98', :quantity => '6'},
      #      {:description => 'Line Item 2', :cost => '6.99', :quantity => '4'}
      #    ],
      #    :vendor_data => [{'repId' => '1234567'}, {'customerId' => '9886'}],
      #    :send_customer_email => true,
      #    :send_merchant_email => true,
      #    :email_text => ['line1', 'line2', 'line3'],
      #    :test_mode => true
      #  )
      #
      def authorize(money, creditcard, options = {})
        post = {}
        post[:PreAuth] = nil
        add_customer_data(post, creditcard, options)
        add_invoice(post, money, options)
        add_creditcard(post, creditcard)
        add_transaction_control(post, options)
        add_vendor_data(post, options)

        commit('Auth', money, post)
      end

      # Performs an authorize and capture in single transaction. In PaymentClearing's
      # documentation this is known as an "Auth" or a "Sale" transaction
      #
      # ==== Parameters
      # * <tt>money</tt> - The amount to be captured. Should be <tt>nil</tt> or an Integer amount in cents.
      # * <tt>creditcard</tt> - The CreditCard details for the transaction
      # * <tt>options</tt> - A Hash of options
      #
      # ==== Options Hash
      # The standard options apply here (:order_id, :ip, :customer, :invoice, :merchant, :description, :email, :currency, :address, :billing_address, :shipping_address), as well as:
      # * <tt>:order_items</tt> - An Array of Hash objects with the keys <tt>:description</tt>, <tt>:cost</tt> (in cents!), and <tt>:quantity</tt>.  If this is provided, <tt>:description</tt> and <tt>money</tt> will be ignored.
      # * <tt>:vendor_data</tt> - An Array of Hash objects with the keys being the name of the VendorData element and value being the value.
      # * <tt>:send_customer_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendCustomerEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:send_merchant_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendMerchantEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:email_text</tt> - An Array of (up to ten (10)) String objects to be included in emails
      # * <tt>:test_mode</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'TestMode' element set to 'TRUE' or 'FALSE'.
      #
      # ==== Examples
      #  response = gateway.purchase(1000, creditcard,
      #    :order_id => '1212', :address => {...}, :email => 'test@test.com',
      #    :order_items => [
      #      {:description => 'Line Item 1', :cost => '8.98', :quantity => '6'},
      #      {:description => 'Line Item 2', :cost => '6.99', :quantity => '4'}
      #    ],
      #    :vendor_data => [{'repId' => '1234567'}, {'customerId' => '9886'}],
      #    :send_customer_email => true,
      #    :send_merchant_email => true,
      #    :email_text => ['line1', 'line2', 'line3'],
      #    :test_mode => true
      #  )
      #
      def purchase(money, creditcard, options = {})
        post = {}
        add_customer_data(post, creditcard, options)
        add_invoice(post, money, options)
        add_creditcard(post, creditcard)
        add_transaction_control(post, options)
        add_vendor_data(post, options)

        commit('Auth', money, post)
      end

      # Captures the funds from an authorize transaction.  In PaymentClearing's
      # documentation this is known as a "PostAuth" transaction.
      #
      # ==== Parameters
      # * <tt>money</tt> - The amount to be captured. Should be an Integer amount in cents
      # * <tt>authorization</tt> - The authorization returned from the previous capture or purchase request
      # * <tt>options</tt> - A Hash of options, all are optional.
      #
      # ==== Options Hash
      # The standard options apply here (:order_id, :ip, :customer, :invoice, :merchant, :description, :email, :currency, :address, :billing_address, :shipping_address), as well as:
      # * <tt>:vendor_data</tt> - An Array of Hash objects with the keys being the name of the VendorData element and value being the value.
      # * <tt>:send_customer_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendCustomerEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:send_merchant_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendMerchantEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:email_text</tt> - An Array of (up to ten (10)) String objects to be included in emails
      # * <tt>:test_mode</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'TestMode' element set to 'TRUE' or 'FALSE'.
      #
      # ==== Examples
      #  response = gateway.capture(1000, creditcard,
      #    :vendor_data => [{'repId' => '1234567'}, {'customerId' => '9886'}],
      #    :send_customer_email => true,
      #    :send_merchant_email => true,
      #    :email_text => ['line1', 'line2', 'line3'],
      #    :test_mode => true
      #  )
      #
      def capture(money, authorization, options = {})
        post = {}
        post[:OperationXID] = authorization
        add_invoice(post, money, options)
        add_transaction_control(post, options)
        add_vendor_data(post, options)

        commit('PostAuth', money, post)
      end

      # This will reverse a previously run transaction which *has* *not* settled.
      #
      # ==== Parameters
      # * <tt>money</tt> - This parameter is ignored -- the PaymentClearing gateway does not allow partial voids.
      # * <tt>authorization</tt> - The authorization returned from the previous capture or purchase request
      # * <tt>options</tt> - A Hash of options, all are optional
      #
      # ==== Options Hash
      # The standard options (:order_id, :ip, :customer, :invoice, :merchant, :description, :email, :currency, :address, :billing_address, :shipping_address) are ignored.
      # * <tt>:vendor_data</tt> - An Array of Hash objects with the keys being the name of the VendorData element and value being the value.
      # * <tt>:send_customer_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendCustomerEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:send_merchant_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendMerchantEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:email_text</tt> - An Array of (up to ten (10)) String objects to be included in emails
      # * <tt>:test_mode</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'TestMode' element set to 'TRUE' or 'FALSE'.
      #
      # ==== Examples
      #  response = gateway.void(nil, '9999999999',
      #    :vendor_data => [{'repId' => '1234567'}, {'customerId' => '9886'}],
      #    :send_customer_email => true,
      #    :send_merchant_email => true,
      #    :email_text => ['line1', 'line2', 'line3'],
      #    :test_mode => true
      #  )
      #
      def void(money, authorization, options = {})
        post = {}
        post[:OperationXID] = authorization
        add_transaction_control(post, options)
        add_vendor_data(post, options)

        commit('Void', money, post)
      end

      # This will reverse a previously run transaction which *has* settled.
      #
      # ==== Parameters
      # * <tt>money</tt> - The amount to be credited. Should be <tt>nil</tt> or an Integer amount in cents
      # * <tt>authorization</tt> - The authorization returned from the previous capture or purchase request
      # * <tt>options</tt> - A Hash of options, all are optional
      #
      # ==== Options Hash
      # The standard options (:order_id, :ip, :customer, :invoice, :merchant, :description, :email, :currency, :address, :billing_address, :shipping_address) are ignored.
      # * <tt>:vendor_data</tt> - An Array of Hash objects with the keys being the name of the VendorData element and value being the value.
      # * <tt>:send_customer_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendCustomerEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:send_merchant_email</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'SendMerchantEmail' element set to 'TRUE' or 'FALSE'.
      # * <tt>:email_text</tt> - An Array of (up to ten (10)) String objects to be included in emails
      # * <tt>:test_mode</tt> - <tt>true</tt> or <tt>false</tt>. Runs the transaction with the 'TestMode' element set to 'TRUE' or 'FALSE'.
      #
      # ==== Examples
      #  response = gateway.credit(nil, '9999999999',
      #    :vendor_data => [{'repId' => '1234567'}, {'customerId' => '9886'}],
      #    :send_customer_email => true,
      #    :send_merchant_email => true,
      #    :email_text => ['line1', 'line2', 'line3'],
      #    :test_mode => true
      #  )
      #
      def credit(money, authorization, options = {})
        post = {}
        post[:OperationXID] = authorization
        add_invoice(post, money, options)
        add_transaction_control(post, options)
        add_vendor_data(post, options)

        commit('TranCredit', money, post)
      end

      private

      def add_customer_data(post, creditcard, options)
        billing_address = options[:billing_address] || options[:address]
        shipping_address = options[:shipping_address] || options[:address]

        post[:CustomerData] = {}

        post[:CustomerData][:Email]  = options[:email] unless options[:email].blank?
        post[:CustomerData][:CustId] = options[:order_id] unless options[:order_id].blank?

        bill_post = post[:CustomerData][:BillingAddress] = {}
        bill_post[:FirstName] = creditcard.first_name || parse_first_name(billing_address[:name])
        bill_post[:LastName]  = creditcard.last_name || parse_last_name(billing_address[:name])
        bill_post[:Address1]  = billing_address[:address1]
        bill_post[:Address2]  = billing_address[:address2] unless billing_address[:address2].blank?
        bill_post[:City]      = billing_address[:city]
        bill_post[:State]     = billing_address[:state]
        bill_post[:Zip]       = billing_address[:zip].to_s
        bill_post[:Country]   = billing_address[:country]
        bill_post[:Phone]     = billing_address[:phone]
        #post[:BillingAddress][:company]   = billing_address[:company]

        unless shipping_address.blank?
          ship_post = post[:CustomerData][:ShippingAddress] = {}
          ship_post[:FirstName] = creditcard.first_name || parse_first_name(shipping_address[:name])
          ship_post[:LastName]  = creditcard.last_name || parse_last_name(shipping_address[:name])
          ship_post[:Address1]  = shipping_address[:address1]
          ship_post[:Address2]  = shipping_address[:address2] unless shipping_address[:address2].blank?
          ship_post[:City]      = shipping_address[:city]
          ship_post[:State]     = shipping_address[:state]
          ship_post[:Zip]       = shipping_address[:zip].to_s
          ship_post[:Country]   = shipping_address[:country]
          ship_post[:Phone]     = shipping_address[:phone]
        end

      end

      def add_invoice(post, money, options)
        post[:AuthCode] = options[:force] if options[:force]
        if options[:order_items].blank?
          post[:Total] = to_dollars(money).to_s unless money.nil? || money < 0.01
          post[:Description] = options[:description] unless options[:description].blank?
        else
          post[:OrderItems] = {:Item => []}
          options[:order_items].each do |item|
            post[:OrderItems][:Item] << {:Description => item[:description],
              :Cost => to_dollars(item[:cost]).to_s, :Qty =>item[:quantity].to_s}
          end
        end
      end

      def add_creditcard(post, creditcard)
        post[:AccountInfo] = {:CardAccount => {
            :AccountNumber => creditcard.number.to_s,
            :ExpirationMonth => creditcard.month.to_s.rjust(2,'0'),
            :ExpirationYear => creditcard.year.to_s
        }}
        unless creditcard.verification_value.blank?
          post[:AccountInfo][:CardAccount][:CVVNumber] = creditcard.verification_value.to_s
        end
      end

      def to_dollars(money_in_cents)
        money_in_cents.to_f/100.0
      end

      def add_transaction_control(post, options)
        post[:TransactionControl] = {}

        # if there was a 'global' option set...
        post[:TransactionControl][:TestMode] = @options[:test_mode].upcase if !@options[:test_mode].blank?
        # allow the global option to be overridden...
        post[:TransactionControl][:TestMode] = options[:test_mode].upcase if !options[:test_mode].blank?

        post[:TransactionControl][:SendCustomerEmail] = options[:send_customer_email].upcase unless options[:send_customer_email].blank?
        post[:TransactionControl][:SendMerchantEmail] = options[:send_merchant_email].upcase unless options[:send_merchant_email].blank?

        if options[:email_text]
          post[:TransactionControl][:EmailText] = Array.new
          options[:email_text].each do |item|
            post[:TransactionControl][:EmailText] << {:EmailTextItem => item}
          end
        end
      end

      def add_vendor_data(post, options)
        return if options[:vendor_data].blank?
        post[:VendorData] = {:Element => []}
        options[:vendor_data].each do |k,v|
          post[:VendorData][:Element] << {:Name => k, :Value => v}
        end
      end

      def commit(action, money, post)
        # Set the Content-Type header -- otherwise the URL decoding messes up
        # the Base64 encoded payload signature!
        response = parse(ssl_post(URL, post_data(action, post), 'Content-Type' => 'text/xml'))

        Response.new(successful?(response), response[:error_message], response,
          :test => test?,
          :authorization => response[:xid],
          :avs_result => { :code => response[:avs_response] },
          :cvv_result => response[:cvv_response])
      end

      def post_data(action, parameters = {})
        payload = parameters.to_xml(:root => "#{action}Transaction",
          :skip_instruct => true, :skip_types => true, :indent => 0)
        #puts "PAYLOAD: #{payload}"
        payload_signature = sign_payload(payload)
        request = "<?xml version=\"1.0\"?>
<GatewayInterface>
<APICredentials>
<Username>#{@options[:login]}</Username>
<PayloadSignature>#{payload_signature}</PayloadSignature>
<TargetGateway>#{@options[:gateway_id]}</TargetGateway>
</APICredentials>
#{payload}
</GatewayInterface>"
#        puts "REQUEST: #{request}"
        request
      end

      def parse(raw_xml)
        #puts "RESPONSE: #{raw_xml}"
        doc = REXML::Document.new(raw_xml)
        response = Hash.new
        transaction_result = doc.root.get_elements('TransactionResponse/TransactionResult/*')
        transaction_result.each do |e|
          #puts "e: #{e.inspect}"
          response[e.name.to_s.underscore.to_sym] = e.text unless e.text.blank?
        end
        #puts "PARSED RESPONSE: #{response.inspect}"
        response
      end

      def successful?(response)
        # Turns out the PaymentClearing gateway is not consistent...
        'ok'.eql?(response[:status].downcase)
      end

      def test_mode?(response)
        # The '1' is a legacy thing; most of the time it should be 'TRUE'...
        'TRUE'.eql?(response[:test_mode]) || '1'.eql?(response[:test_mode])
      end

      def message_from(response)
        response[:error_message]
      end

      def sign_payload(payload)
        key = @options[:password].to_s
        digest=OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new(key), key, payload)
        actual_signature = Base64.b64encode(digest)
        actual_signature.chomp!
      end
    end
  end
end

