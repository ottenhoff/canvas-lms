#
# Copyright (C) 2011 - 2014 Instructure, Inc.
#
# This file is part of Canvas.
#
# Canvas is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3 of the License.
#
# Canvas is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.
#

require 'vericite/response'
require 'vericite_api'

module VeriCite
  def self.state_from_similarity_score(similarity_score)
    return 'none' if similarity_score == 0
    return 'acceptable' if similarity_score < 25
    return 'warning' if similarity_score < 50
    return 'problem' if similarity_score < 75
    'failure'
  end

  class Client
    attr_accessor :endpoint, :account_id, :shared_secret, :host, :testing

    def initialize(account_id, shared_secret, host=nil, testing=false)
      @host = host || "api.vericite.com"
      @endpoint = "/api.asp"
      raise "Account ID required" unless account_id
      raise "Shared secret required" unless shared_secret
      @account_id = account_id
      @shared_secret = shared_secret
      @testing = testing
      @functions = {
        :create_user              => '1', # instructor or student
        :create_course            => '2', # instructor only
        :enroll_student           => '3', # student only
        :create_assignment        => '4', # instructor only
        :submit_paper             => '5', # student or teacher
        :generate_report          => '6',
        :show_paper               => '7',
        :delete_paper             => '8',
        :change_password          => '9',
        :list_papers              => '10',
        :check_user_paper         => '11',
        :view_admin_statistics    => '12',
        :view_grade_mark          => '13',
        :report_turnaround_times  => '14',
        :submission_scores        => '15',
        :login_user               => '17',
        :logout_user              => '18',
      }
    end

    def id(obj)
      if @testing
        "test_#{obj.asset_string}"
      elsif obj.respond_to?(:vericite_id)
        obj.vericite_asset_string
      else
        "#{account_id}_#{obj.asset_string}"
      end
    end

    def email(item)
      # emails @example.com are, guaranteed by RFCs, to be like /dev/null :)
      email = if item.is_a?(User)
                item.email
              elsif item.respond_to?(:vericite_id)
                "#{item.vericite_asset_string}@null.instructure.example.com"
              end
      email ||= "#{item.asset_string}@null.instructure.example.com"
    end

    VeriCiteUser = Struct.new(:asset_string,:first_name,:last_name,:name)

    def testSettings
      user = VeriCiteUser.new("admin_test","Admin","Test","Admin Test")
      res = createTeacher(user)
      res.success?
    end

    def createStudent(user)
      sendRequest(:create_user, 2, :user => user, :utp => '1')
    end

    def createTeacher(user)
      sendRequest(:create_user, 2, :user => user, :utp => '2')
    end

    def createCourse(course)
      sendRequest(:create_course, 2, :course => course, :user => course, :utp => '2')
    end

    def enrollStudent(course, student)
      sendRequest(:enroll_student, 2, :user => student, :course => course, :utp => '1', :tem => email(course))
    end

    def self.default_assignment_vericite_settings
      {
        :originality_report_visibility => 'immediate',
        :exclude_quoted => '1'
      }
    end

    def self.normalize_assignment_vericite_settings(settings)
      unless settings.nil?
        valid_keys = VeriCite::Client.default_assignment_vericite_settings.keys
        valid_keys << :created
        settings = settings.slice(*valid_keys)

        settings[:originality_report_visibility] = 'immediate' unless ['immediate', 'after_grading', 'after_due_date', 'never'].include?(settings[:originality_report_visibility])
        settings[:s_view_report] =  determine_student_visibility(settings[:originality_report_visibility])

        [:exclude_quoted].each do |key|
          bool = Canvas::Plugin.value_to_boolean(settings[key])
          settings[key] = bool ? '1' : '0'
        end
      end
      settings
    end

    def self.determine_student_visibility(originality_report_visibility)
      case originality_report_visibility
      when 'immediate', 'after_grading', 'after_due_date'
        "1"
      when 'never'
        "0"
      end
    end

    def createOrUpdateAssignment(assignment, settings)
      course = assignment.context
      # vericite generally expects the timezone to be set the same as
      # the vericite account is set up as.
      today = course.time_zone.today
      settings = VeriCite::Client.normalize_assignment_vericite_settings(settings)

      response = sendRequest(:create_assignment, settings.delete(:created) ? '3' : '2', settings.merge!({
        :user => course,
        :course => course,
        :assignment => assignment,
        :utp => '2',
        :dtstart => "#{today.strftime} 00:00:00",
        :dtdue => "#{today.strftime} 00:00:00",
        :dtpost => "#{today.strftime} 00:00:00",
        :late_accept_flag => '1',
        :post => true
      }))

      response.success? ? { assignment_id: response.assignment_id } : response.error_hash
    end

    # if asset_string is passed in, only submit that attachment
    def submitPaper(submission, asset_string=nil)
      student = submission.user
      assignment = submission.assignment
      course = assignment.context
      opts = {
        :post => true,
        :utp => '1',
        :user => student,
        :course => course,
        :assignment => assignment,
        :tem => email(course)
      }
      responses = {}
      if submission.submission_type == 'online_upload'
        attachments = submission.attachments.select{ |a| a.vericiteable? && (asset_string.nil? || a.asset_string == asset_string) }
        attachments.each do |a|
          responses[a.asset_string] = sendRequest(:submit_paper, '2', { :ptl => a.display_name, :pdata => a.open(), :ptype => '2' }.merge!(opts))
        end
      elsif submission.submission_type == 'online_text_entry' && (asset_string.nil? || submission.asset_string == asset_string)
        responses[submission.asset_string] = sendRequest(:submit_paper, '2', { :ptl => assignment.title, :pdata => submission.plaintext_body, :ptype => "1" }.merge!(opts))
      else
        raise "Unsupported submission type for VeriCite integration: #{submission.submission_type}"
      end

      responses.keys.each do |asset_string|
        res = responses[asset_string]
        responses[asset_string] = res.success? ? {object_id: res.returned_object_id} : res.error_hash
      end

      responses
    end

    def generateReport(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data[asset_string][:object_id] rescue nil
      res = nil
      res = sendRequest(:generate_report, 2, :oid => object_id, :utp => '2', :user => course, :course => course, :assignment => assignment) if object_id
      data = {}
      if res
        data[:similarity_score] = res.css("originalityscore").first.try(:content)
        data[:web_overlap] = res.css("web_overlap").first.try(:content)
        data[:publication_overlap] = res.css("publication_overlap").first.try(:content)
        data[:student_overlap] = res.css("student_paper_overlap").first.try(:content)
      end
      data
    end

    def submissionReportUrl(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data[asset_string][:object_id] rescue nil
      sendRequest(:generate_report, 1, :oid => object_id, :utp => '2', :user => course, :course => course, :assignment => assignment)
    end

    def submissionStudentReportUrl(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data[asset_string][:object_id] rescue nil
      sendRequest(:generate_report, 1, :oid => object_id, :utp => '1', :user => user, :course => course, :assignment => assignment, :tem => email(course))
    end

    def submissionPreviewUrl(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data[asset_string][:object_id] rescue nil
      sendRequest(:show_paper, 1, :oid => object_id, :utp => '1', :user => user, :course => course, :assignment => assignment, :tem => email(course))
    end

    def submissionDownloadUrl(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data[asset_string][:object_id] rescue nil
      sendRequest(:show_paper, 1, :oid => object_id, :utp => '1', :user => user, :course => course, :assignment => assignment, :tem => email(course))
    end

    def listSubmissions(assignment)
      course = assignment.context
      sendRequest(:list_papers, 2, :assignment => assignment, :course => course, :user => course, :utp => '1', :tem => email(course))
    end

    def request_md5(params)
      keys_used = []
      str = ""
      keys = [:aid,:assign,:assignid,:cid,:cpw,:ctl,:diagnostic,:dis,:dtdue,:dtstart,:dtpost,:encrypt,:fcmd,:fid,:gmtime,:newassign,:newupw,:oid,:pfn,:pln,:ptl,:ptype,:said,:tem,:uem,:ufn,:uid,:uln,:upw,:utp]
      keys.each do |key|
        keys_used << key if params[key] && !params[key].empty?
        str += (params[key] || "")
      end
      str += @shared_secret
      Digest::MD5.hexdigest(str)
    end

    def escape_params(params)
      escaped_params = {}
      params.each do |key, value|
        if value.is_a?(String)
          escaped_params[key] = CGI.escape(value).gsub("+", "%20")
          # vericite uses %20 to encode spaces (instead of +)
        else
          escaped_params[key] = value
        end
      end
      return escaped_params
    end

    def prepare_params(command, fcmd, args)
      user = args.delete :user
      course = args.delete :course
      assignment = args.delete :assignment
      post = args.delete :post
      params = args.merge({
        :gmtime => Time.now.utc.strftime("%Y%m%d%H%M")[0,11],
        :fid => @functions[command],
        :fcmd => fcmd.to_s,
        :encrypt => '0',
        :aid => @account_id,
        :src => '15',
        :dis => '1'
      })
      if user
        params[:uid] = id(user)
        params[:uem] = email(user)
        if user.is_a?(Course)
          params[:ufn] = user.name
          params[:uln] = "Course"
        else
          params[:ufn] = user.first_name
          params[:uln] = user.last_name
          params[:uln] = "Student" if params[:uln].empty?
        end
      end
      if course
        params[:cid] = id(course)
        params[:ctl] = course.name
      end
      if assignment
        params[:assign] = "#{assignment.title} - #{assignment.id}"
        params[:assignid] = id(assignment)
      end
      params[:diagnostic] = "1" if @testing

      params[:md5] = request_md5(params)
      params = escape_params(params) if post
      return params
    end

    def sendRequest(command, fcmd, args)
      require 'net/http'
      
      
      Rails.logger.info("VeriCite API sendRequest: course: #{command}, assignment: #{fcmd}, settings: #{args}");
      
      vericite_client = VeriCiteClient::ApiClient.new();
      
      if command == :create_assignment
        Rails.logger.info("VeriCite API sendRequest calling create_assignment");
      end

      # post = args[:post] # gets deleted in prepare_params
      # params = prepare_params(command, fcmd, args)
# 
      # if post
        # mp = Multipart::Post.new
        # query, headers = mp.prepare_query(params)
        # http = Net::HTTP.new(@host, 443)
        # http.use_ssl = true
        # http_response = http.start{|con|
          # req = Net::HTTP::Post.new(@endpoint, headers)
          # con.read_timeout = 30
          # begin
            # res = con.request(req, query)
          # rescue => e
            # Rails.logger.error("VeriCite API error for account_id #{@account_id}: POSTING FAILED")
            # Rails.logger.error(params.to_json)
          # end
        # }
      # else
        # requestParams = ""
        # params.each do |key, value|
          # next if value.nil?
          # requestParams += "&#{URI.escape(key.to_s)}=#{CGI.escape(value.to_s)}"
        # end
        # if params[:fcmd] == '1'
          # return "https://#{@host}#{@endpoint}?#{requestParams}"
        # else
          # http = Net::HTTP.new(@host, 443)
          # http.use_ssl = true
          # http_response = http.start{|conn|
            # conn.get("#{@endpoint}?#{requestParams}")
          # }
        # end
      # end

      return nil if @testing

      response = VeriCite::Response.new()
      if response.error?
        Rails.logger.error("VeriCite API error for account_id #{@account_id}: error #{ response.return_code }")
        Rails.logger.error(params.to_json)
        Rails.logger.error(http_response.body)
      end
      response

    end
  end
end
