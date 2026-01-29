#!/usr/bin/env ruby
# Pseudonym Generator - Creates realistic fake identities
# Part of Lackadaisical Anonymity Toolkit

require 'json'
require 'date'
require 'digest'
require 'faker'
require 'securerandom'

class PseudonymGenerator
  attr_reader :locale
  
  def initialize(locale = :en)
    @locale = locale
    Faker::Config.locale = locale
  end
  
  def generate_identity(options = {})
    identity = {
      personal: generate_personal_info(options),
      contact: generate_contact_info(options),
      financial: generate_financial_info(options),
      online: generate_online_info(options),
      documents: generate_document_info(options),
      background: generate_background_info(options)
    }
    
    # Add metadata
    identity[:metadata] = {
      generated_at: Time.now.utc.iso8601,
      locale: @locale,
      version: '1.0',
      seed: options[:seed] || SecureRandom.hex(8)
    }
    
    identity
  end
  
  private
  
  def generate_personal_info(options)
    gender = options[:gender] || [:male, :female].sample
    
    first_name = gender == :male ? Faker::Name.male_first_name : Faker::Name.female_first_name
    middle_name = Faker::Name.middle_name
    last_name = Faker::Name.last_name
    
    birthdate = generate_birthdate(options[:age_range])
    
    {
      first_name: first_name,
      middle_name: middle_name,
      last_name: last_name,
      full_name: "#{first_name} #{middle_name} #{last_name}",
      nickname: generate_nickname(first_name),
      gender: gender.to_s,
      birthdate: birthdate.to_s,
      age: calculate_age(birthdate),
      birthplace: generate_birthplace,
      nationality: options[:nationality] || Faker::Nation.nationality,
      ethnicity: Faker::Demographic.race,
      height: generate_height(gender),
      weight: generate_weight(gender),
      eye_color: Faker::Color.color_name,
      hair_color: Faker::Color.color_name,
      blood_type: generate_blood_type
    }
  end
  
  def generate_contact_info(options)
    {
      email: {
        primary: Faker::Internet.email,
        secondary: Faker::Internet.email,
        disposable: generate_disposable_email
      },
      phone: {
        mobile: Faker::PhoneNumber.cell_phone,
        home: Faker::PhoneNumber.phone_number,
        work: Faker::PhoneNumber.phone_number
      },
      address: {
        street: Faker::Address.street_address,
        secondary: Faker::Address.secondary_address,
        city: Faker::Address.city,
        state: Faker::Address.state,
        zip: Faker::Address.zip_code,
        country: Faker::Address.country,
        coordinates: {
          latitude: Faker::Address.latitude,
          longitude: Faker::Address.longitude
        }
      }
    }
  end
  
  def generate_financial_info(options)
    {
      credit_card: {
        number: Faker::Finance.credit_card,
        type: Faker::Business.credit_card_type,
        expiry: Faker::Business.credit_card_expiry_date.strftime("%m/%y"),
        cvv: Faker::Number.number(digits: 3)
      },
      bank_account: {
        iban: Faker::Bank.iban,
        bic: Faker::Bank.swift_bic,
        account_number: Faker::Bank.account_number,
        routing_number: Faker::Bank.routing_number
      },
      bitcoin: {
        address: generate_bitcoin_address,
        private_key: SecureRandom.hex(32)
      },
      income: {
        annual: Faker::Number.between(from: 20000, to: 200000),
        monthly: Faker::Number.between(from: 1500, to: 15000),
        currency: Faker::Currency.code
      }
    }
  end
  
  def generate_online_info(options)
    username = generate_username
    
    {
      username: username,
      passwords: {
        strong: generate_strong_password,
        memorable: generate_memorable_password
      },
      social_media: {
        twitter: "@#{username}",
        instagram: username.downcase,
        facebook: "#{username}.#{Faker::Number.number(digits: 4)}",
        linkedin: "#{username}-#{SecureRandom.hex(3)}",
        reddit: "u/#{username}_#{SecureRandom.hex(2)}"
      },
      avatar: {
        url: Faker::Avatar.image,
        gravatar: generate_gravatar_url
      },
      user_agent: Faker::Internet.user_agent,
      mac_address: Faker::Internet.mac_address,
      ipv4: Faker::Internet.ip_v4_address,
      ipv6: Faker::Internet.ip_v6_address
    }
  end
  
  def generate_document_info(options)
    {
      passport: {
        number: generate_passport_number,
        issued_date: Faker::Date.backward(days: 1825),
        expiry_date: Faker::Date.forward(days: 3650),
        issuing_country: Faker::Address.country_code
      },
      drivers_license: {
        number: generate_drivers_license,
        class: ['A', 'B', 'C', 'D', 'E'].sample,
        issued_date: Faker::Date.backward(days: 2920),
        expiry_date: Faker::Date.forward(days: 1460),
        state: Faker::Address.state_abbr
      },
      ssn: generate_ssn,
      tax_id: generate_tax_id
    }
  end
  
  def generate_background_info(options)
    {
      education: {
        high_school: {
          name: "#{Faker::Address.city} High School",
          graduation_year: Faker::Date.backward(days: 7300).year
        },
        university: {
          name: Faker::University.name,
          degree: Faker::Educator.degree,
          major: Faker::Educator.subject,
          graduation_year: Faker::Date.backward(days: 3650).year
        }
      },
      employment: {
        company: Faker::Company.name,
        position: Faker::Job.title,
        department: Faker::Commerce.department,
        start_date: Faker::Date.backward(days: 1095),
        salary: Faker::Number.between(from: 30000, to: 150000)
      },
      family: {
        marital_status: ['single', 'married', 'divorced', 'widowed'].sample,
        children: Faker::Number.between(from: 0, to: 3),
        spouse_name: Faker::Name.name,
        emergency_contact: {
          name: Faker::Name.name,
          relationship: ['spouse', 'parent', 'sibling', 'friend'].sample,
          phone: Faker::PhoneNumber.phone_number
        }
      },
      interests: generate_interests,
      personality: {
        mbti: generate_mbti,
        zodiac: Faker::Zodiac.sign,
        chinese_zodiac: Faker::Zodiac.chinese_zodiac
      }
    }
  end
  
  # Helper methods
  
  def generate_birthdate(age_range = nil)
    age_range ||= (18..65)
    age = rand(age_range)
    Date.today - (age * 365) - rand(365)
  end
  
  def calculate_age(birthdate)
    ((Date.today - birthdate) / 365.25).floor
  end
  
  def generate_birthplace
    "#{Faker::Address.city}, #{Faker::Address.state}, #{Faker::Address.country}"
  end
  
  def generate_height(gender)
    base = gender == :male ? 175 : 162
    "#{base + rand(-15..15)} cm"
  end
  
  def generate_weight(gender)
    base = gender == :male ? 75 : 60
    "#{base + rand(-15..20)} kg"
  end
  
  def generate_blood_type
    types = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
    types.sample
  end
  
  def generate_nickname(first_name)
    nicknames = {
      'James' => ['Jim', 'Jimmy', 'Jamie'],
      'Robert' => ['Bob', 'Rob', 'Bobby'],
      'William' => ['Will', 'Bill', 'Billy'],
      'Elizabeth' => ['Liz', 'Beth', 'Lizzy'],
      'Margaret' => ['Maggie', 'Meg', 'Peggy']
    }
    
    nicknames[first_name]&.sample || first_name[0..2].downcase
  end
  
  def generate_disposable_email
    domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com']
    "#{SecureRandom.hex(8)}@#{domains.sample}"
  end
  
  def generate_bitcoin_address
    # Simplified Bitcoin address generation (not cryptographically valid)
    prefix = ['1', '3', 'bc1'].sample
    chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a - ['0', 'O', 'I', 'l']
    address = prefix + (0...33).map { chars.sample }.join
    address[0...34]
  end
  
  def generate_username
    adjectives = ['swift', 'silent', 'clever', 'brave', 'wild']
    nouns = ['fox', 'eagle', 'wolf', 'shark', 'hawk']
    "#{adjectives.sample}#{nouns.sample}#{rand(100..999)}"
  end
  
  def generate_strong_password
    chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a + '!@#$%^&*'.chars
    (0...16).map { chars.sample }.join
  end
  
  def generate_memorable_password
    words = [Faker::Hacker.noun, Faker::Hacker.verb, Faker::Hacker.adjective]
    words.map(&:capitalize).join + rand(10..99).to_s + ['!', '@', '#'].sample
  end
  
  def generate_gravatar_url
    email = Faker::Internet.email
    hash = Digest::MD5.hexdigest(email.downcase.strip)
    "https://www.gravatar.com/avatar/#{hash}"
  end
  
  def generate_passport_number
    letters = ('A'..'Z').to_a
    "#{letters.sample}#{letters.sample}#{rand(1000000..9999999)}"
  end
  
  def generate_drivers_license
    "#{('A'..'Z').to_a.sample}#{rand(100..999)}-#{rand(100..999)}-#{rand(10..99)}-#{rand(100..999)}"
  end
  
  def generate_ssn
    "#{rand(100..999)}-#{rand(10..99)}-#{rand(1000..9999)}"
  end
  
  def generate_tax_id
    "#{rand(10..99)}-#{rand(1000000..9999999)}"
  end
  
  def generate_interests
    categories = {
      sports: ['football', 'basketball', 'tennis', 'swimming', 'running'],
      hobbies: ['reading', 'cooking', 'gaming', 'photography', 'gardening'],
      music: ['rock', 'jazz', 'classical', 'electronic', 'pop'],
      travel: ['beaches', 'mountains', 'cities', 'cultural sites', 'adventure']
    }
    
    selected = {}
    categories.each do |category, items|
      selected[category] = items.sample(rand(1..3))
    end
    selected
  end
  
  def generate_mbti
    dimensions = [
      ['E', 'I'],  # Extraversion/Introversion
      ['S', 'N'],  # Sensing/Intuition
      ['T', 'F'],  # Thinking/Feeling
      ['J', 'P']   # Judging/Perceiving
    ]
    dimensions.map { |d| d.sample }.join
  end
end

# CLI interface
if __FILE__ == $0
  require 'optparse'
  
  options = {}
  OptionParser.new do |opts|
    opts.banner = "Usage: pseudonym_generator.rb [options]"
    
    opts.on("-l", "--locale LOCALE", "Set locale (default: en)") do |l|
      options[:locale] = l.to_sym
    end
    
    opts.on("-g", "--gender GENDER", "Set gender (male/female)") do |g|
      options[:gender] = g.to_sym
    end
    
    opts.on("-a", "--age MIN-MAX", "Set age range (e.g., 25-35)") do |a|
      min, max = a.split('-').map(&:to_i)
      options[:age_range] = (min..max)
    end
    
    opts.on("-o", "--output FILE", "Output to file") do |f|
      options[:output] = f
    end
    
    opts.on("-f", "--format FORMAT", "Output format (json/yaml)") do |f|
      options[:format] = f.to_sym
    end
  end.parse!
  
  generator = PseudonymGenerator.new(options[:locale] || :en)
  identity = generator.generate_identity(options)
  
  output = case options[:format]
  when :yaml
    require 'yaml'
    identity.to_yaml
  else
    JSON.pretty_generate(identity)
  end
  
  if options[:output]
    File.write(options[:output], output)
    puts "Identity saved to #{options[:output]}"
  else
    puts output
  end
end
