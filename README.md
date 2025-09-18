This is a pragmatic, production-ready kernel for a modular CRM you can scaffold in Rails. It sticks to classic MVC, keeps the core small, and leaves room for extension modules (Forms, Products, Omnichannel, etc.).

---

## 0) Tech choices
- **Rails**: 8+ (with Hotwire/Turbo by default)
- **Ruby**: 3.4+
- **DB**: Postgres 14+
- **Auth**: Devise (or Authlogic/Bcrypt if you prefer)
- **Jobs**: ActiveJob + Sidekiq
- **Storage**: ActiveStorage (S3, GCS, or local)
- **AuthZ**: Pundit
- **Search**: PostgreSQL full text (simple), upgrade later if needed

> Multi-tenancy is **row-scoped** via `account_id` + `Current.account`, with hard FK constraints and policy checks at the controller/service layer.

---

## 1) Domain model (Core)
Core focuses on primitives shared by all modules.

### Entities
- **Account** – workspace/tenant
- **User** – belongs to Account; has **role** (owner/admin/member)
- **Company** – optional organization record
- **Contact** – person; can belong to a company
- **Pipeline** – a board of stages (e.g., Sales, Onboarding)
- **Stage** – ordered steps inside a pipeline
- **Deal** – the thing that moves through a pipeline (opportunity/application)
- **Activity** – timeline items on Contact/Deal (note, task, call, email)
- **Tag** & **Tagging** – polymorphic labels
- **DomainEvent** – append-only event log emitted by models
- **Automation** – trigger + condition + actions (JSON config)
- **ApiKey** – programmatic access
- **WebhookEndpoint** – outgoing webhooks to external URLs

### Minimal ERD (FKs)
```
Account 1—* User
Account 1—* Company
Account 1—* Contact (*—1 Company optional)
Account 1—* Pipeline 1—* Stage
Account 1—* Deal (1—1 Contact, 0—1 Company, 1—1 Pipeline, 1—1 Stage)
Deal 1—* Activity (polymorphic: also Contact can have activities)
(Tag) *—* (Contact|Deal|Company) via Tagging
Account 1—* DomainEvent
Account 1—* Automation
Account 1—* ApiKey
Account 1—* WebhookEndpoint
```

---

## 2) Database schema (migrations)
**Conventions**
- Every table has `id uuid`, `account_id uuid`, timestamps, and appropriate indexes.
- Flexible fields live in `jsonb` columns with GIN indexes.
- Use enums as strings to keep migrations simple early on.

```ruby
# db/migrate/202409010001_create_accounts.rb
class CreateAccounts < ActiveRecord::Migration[7.1]
  def change
    enable_extension "pgcrypto"

    create_table :accounts, id: :uuid do |t|
      t.string :name, null: false
      t.string :subdomain, null: false, index: { unique: true }
      t.timestamps
    end
  end
end

# db/migrate/202409010002_create_users.rb
class CreateUsers < ActiveRecord::Migration[7.1]
  def change
    create_table :users, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      ## Devise
      t.string :email,              null: false, default: ""
      t.string :encrypted_password, null: false, default: ""
      t.string :role, null: false, default: "member" # owner|admin|member
      t.string :name
      t.timestamps
    end
    add_index :users, [:account_id, :email], unique: true
    add_foreign_key :users, :accounts
  end
end

# db/migrate/202409010010_create_companies.rb
class CreateCompanies < ActiveRecord::Migration[7.1]
  def change
    create_table :companies, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :name, null: false
      t.jsonb :custom_fields, null: false, default: {}
      t.timestamps
    end
    add_index :companies, :custom_fields, using: :gin
    add_foreign_key :companies, :accounts
  end
end

# db/migrate/202409010011_create_contacts.rb
class CreateContacts < ActiveRecord::Migration[7.1]
  def change
    create_table :contacts, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.uuid :company_id, index: true
      t.string :first_name
      t.string :last_name
      t.string :email
      t.string :phone
      t.jsonb :custom_fields, null: false, default: {}
      t.timestamps
    end
    add_index :contacts, [:account_id, :email]
    add_index :contacts, :custom_fields, using: :gin
    add_foreign_key :contacts, :accounts
    add_foreign_key :contacts, :companies
  end
end

# db/migrate/202409010020_create_pipelines_stages.rb
class CreatePipelinesStages < ActiveRecord::Migration[7.1]
  def change
    create_table :pipelines, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :name, null: false
      t.timestamps
    end
    add_foreign_key :pipelines, :accounts

    create_table :stages, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.uuid :pipeline_id, null: false, index: true
      t.string :name, null: false
      t.integer :position, null: false, default: 0
      t.timestamps
    end
    add_foreign_key :stages, :accounts
    add_foreign_key :stages, :pipelines
  end
end

# db/migrate/202409010030_create_deals.rb
class CreateDeals < ActiveRecord::Migration[7.1]
  def change
    create_table :deals, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.uuid :contact_id, null: false, index: true
      t.uuid :company_id, index: true
      t.uuid :pipeline_id, null: false, index: true
      t.uuid :stage_id, null: false, index: true
      t.string :title, null: false
      t.string :status, null: false, default: "open" # open|won|lost
      t.decimal :amount, precision: 12, scale: 2
      t.date :expected_close_on
      t.jsonb :custom_fields, null: false, default: {}
      t.timestamps
    end
    add_index :deals, [:account_id, :pipeline_id, :stage_id]
    add_index :deals, :custom_fields, using: :gin
    add_foreign_key :deals, :accounts
    add_foreign_key :deals, :contacts
    add_foreign_key :deals, :companies
    add_foreign_key :deals, :pipelines
    add_foreign_key :deals, :stages
  end
end

# db/migrate/202409010040_create_activities.rb
class CreateActivities < ActiveRecord::Migration[7.1]
  def change
    create_table :activities, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :activity_type, null: false # note|task|call|email
      t.uuid :actor_id, index: true # user who did it
      t.string :subject
      t.text :body
      t.datetime :due_at
      t.boolean :completed, default: false
      t.references :subjectable, polymorphic: true, type: :uuid, null: false
      t.jsonb :metadata, null: false, default: {}
      t.timestamps
    end
    add_index :activities, :metadata, using: :gin
    add_foreign_key :activities, :accounts
    add_foreign_key :activities, :users, column: :actor_id
  end
end

# db/migrate/202409010050_create_tags_and_taggings.rb
class CreateTagsAndTaggings < ActiveRecord::Migration[7.1]
  def change
    create_table :tags, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :name, null: false
      t.timestamps
    end
    add_index :tags, [:account_id, :name], unique: true
    add_foreign_key :tags, :accounts

    create_table :taggings, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.uuid :tag_id, null: false, index: true
      t.references :taggable, polymorphic: true, type: :uuid, null: false
      t.timestamps
    end
    add_index :taggings, [:tag_id, :taggable_type, :taggable_id], unique: true, name: 'idx_unique_tagging'
    add_foreign_key :taggings, :accounts
    add_foreign_key :taggings, :tags
  end
end

# db/migrate/202409010060_create_events_automations_integrations.rb
class CreateEventsAutomationsIntegrations < ActiveRecord::Migration[7.1]
  def change
    create_table :domain_events, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :event_type, null: false # e.g., deal.created, stage.changed
      t.string :entity_type, null: false
      t.uuid :entity_id, null: false
      t.jsonb :payload, null: false, default: {}
      t.datetime :occurred_at, null: false
      t.timestamps
    end
    add_index :domain_events, :payload, using: :gin
    add_foreign_key :domain_events, :accounts

    create_table :automations, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :name, null: false
      t.boolean :active, default: true
      t.string :trigger_event, null: false # e.g., deal.created
      t.jsonb :condition_json, null: false, default: {} # JSONLogic
      t.jsonb :actions_json, null: false, default: []  # array of actions
      t.timestamps
    end
    add_foreign_key :automations, :accounts

    create_table :api_keys, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :name, null: false
      t.string :token_digest, null: false
      t.datetime :last_used_at
      t.boolean :active, default: true
      t.timestamps
    end
    add_index :api_keys, [:account_id, :name], unique: true
    add_foreign_key :api_keys, :accounts

    create_table :webhook_endpoints, id: :uuid do |t|
      t.uuid :account_id, null: false, index: true
      t.string :name, null: false
      t.string :url, null: false
      t.string :secret
      t.boolean :active, default: true
      t.timestamps
    end
    add_foreign_key :webhook_endpoints, :accounts
  end
end
```

---

## 3) Models (domain logic, callbacks)
```ruby
# app/models/concerns/belongs_to_account.rb
module BelongsToAccount
  extend ActiveSupport::Concern
  included do
    belongs_to :account
    validates :account_id, presence: true
  end
end

# app/models/account.rb
class Account < ApplicationRecord
  has_many :users, dependent: :destroy
end

# app/models/user.rb
class User < ApplicationRecord
  include BelongsToAccount
  devise :database_authenticatable, :registerable, :recoverable,
         :rememberable, :validatable
  enum :role, { owner: "owner", admin: "admin", member: "member" }, prefix: true
end

# app/models/company.rb
class Company < ApplicationRecord
  include BelongsToAccount
  has_many :contacts, dependent: :nullify
  has_many :deals, dependent: :nullify
  validates :name, presence: true
end

# app/models/contact.rb
class Contact < ApplicationRecord
  include BelongsToAccount
  belongs_to :company, optional: true
  has_many :deals, dependent: :destroy
  has_many :activities, as: :subjectable, dependent: :destroy
  has_many :taggings, as: :taggable, dependent: :destroy
  has_many :tags, through: :taggings

  validates :email, uniqueness: { scope: :account_id }, allow_blank: true
  after_commit :emit_created_event, on: :create

  def full_name = [first_name, last_name].compact.join(" ")

  private
  def emit_created_event
    DomainEvent.emit!(account:, event_type: "contact.created", entity: self, payload: attributes)
  end
end

# app/models/pipeline.rb
class Pipeline < ApplicationRecord
  include BelongsToAccount
  has_many :stages, -> { order(position: :asc) }, dependent: :destroy
  has_many :deals
  validates :name, presence: true
end

# app/models/stage.rb
class Stage < ApplicationRecord
  include BelongsToAccount
  belongs_to :pipeline
  has_many :deals
  validates :name, presence: true
  validates :position, presence: true
end

# app/models/deal.rb
class Deal < ApplicationRecord
  include BelongsToAccount
  belongs_to :contact
  belongs_to :company, optional: true
  belongs_to :pipeline
  belongs_to :stage
  has_many :activities, as: :subjectable, dependent: :destroy
  has_many :taggings, as: :taggable, dependent: :destroy
  has_many :tags, through: :taggings

  validates :title, presence: true
  validates :status, inclusion: { in: %w[open won lost] }

  after_commit :emit_created_event, on: :create
  after_update :emit_stage_change, if: :saved_change_to_stage_id?
  after_update :emit_status_change, if: :saved_change_to_status?

  private
  def emit_created_event
    DomainEvent.emit!(account:, event_type: "deal.created", entity: self, payload: attributes)
  end
  def emit_stage_change
    DomainEvent.emit!(account:, event_type: "deal.stage_changed", entity: self,
                      payload: { from: stage_id_before_last_save, to: stage_id })
  end
  def emit_status_change
    DomainEvent.emit!(account:, event_type: "deal.status_changed", entity: self,
                      payload: { from: status_before_last_save, to: status })
  end
end

# app/models/activity.rb
class Activity < ApplicationRecord
  include BelongsToAccount
  belongs_to :subjectable, polymorphic: true
  belongs_to :actor, class_name: "User", optional: true
  validates :activity_type, inclusion: { in: %w[note task call email] }
end

# app/models/tag.rb
class Tag < ApplicationRecord
  include BelongsToAccount
  has_many :taggings, dependent: :destroy
  validates :name, presence: true
end

# app/models/tagging.rb
class Tagging < ApplicationRecord
  include BelongsToAccount
  belongs_to :tag
  belongs_to :taggable, polymorphic: true
end

# app/models/domain_event.rb
class DomainEvent < ApplicationRecord
  include BelongsToAccount

  def self.emit!(account:, event_type:, entity:, payload: {})
    event = create!(account:, event_type:, entity_type: entity.class.name,
                    entity_id: entity.id, payload:, occurred_at: Time.current)
    AutomationRunnerJob.perform_later(event.id)
    WebhookDispatchJob.perform_later(event.id)
    event
  end
end

# app/models/automation.rb
class Automation < ApplicationRecord
  include BelongsToAccount
  scope :active, -> { where(active: true) }
end

# app/models/api_key.rb
class ApiKey < ApplicationRecord
  include BelongsToAccount
  has_secure_password :token, validations: false # store digest in token_digest
  before_create :set_token
  def set_token
    raw = SecureRandom.hex(20)
    self.token = raw
    @raw_token = raw
  end
  def raw_token = @raw_token
end

# app/models/webhook_endpoint.rb
class WebhookEndpoint < ApplicationRecord
  include BelongsToAccount
end
```

---

## 4) Service layer & Jobs
Keep controllers skinny; put orchestration here.

```ruby
# app/services/current.rb
class Current < ActiveSupport::CurrentAttributes
  attribute :account, :user
end

# app/services/automations/json_logic.rb
module Automations
  class JsonLogic
    # Minimal JSONLogic evaluator for ==, >, <, >=, <=, and/or/not, var
    def self.apply(rule, data)
      case rule
      when Hash
        op, arg = rule.first
        case op.to_s
        when "==" then eval2(arg[0], data) == eval2(arg[1], data)
        when ">"  then eval2(arg[0], data) >  eval2(arg[1], data)
        when ">=" then eval2(arg[0], data) >= eval2(arg[1], data)
        when "<"  then eval2(arg[0], data) <  eval2(arg[1], data)
        when "<=" then eval2(arg[0], data) <= eval2(arg[1], data)
        when "and" then arg.all? { |a| apply(a, data) }
        when "or"  then arg.any? { |a| apply(a, data) }
        when "not" then !apply(arg, data)
        when "var" then data.dig(*arg.to_s.split('.'))
        else
          false
        end
      else
        rule
      end
    end
    def self.eval2(x, data); x.is_a?(Hash) ? apply(x, data) : x end
  end
end

# app/jobs/automation_runner_job.rb
class AutomationRunnerJob < ApplicationJob
  queue_as :default
  def perform(event_id)
    event = DomainEvent.find(event_id)
    automations = Automation.active.where(account_id: event.account_id, trigger_event: event.event_type)
    context = build_context(event)
    automations.find_each do |auto|
      next unless Automations::JsonLogic.apply(auto.condition_json, context)
      auto.actions_json.each { |action| dispatch_action(action, event, context) }
    end
  end

  def build_context(event)
    base = {
      "event" => {
        "type" => event.event_type,
        "entity_type" => event.entity_type,
        "entity_id" => event.entity_id
      },
      "payload" => event.payload
    }
    # Inline some entity snapshot for convenience
    if event.entity_type == "Deal"
      deal = Deal.find(event.entity_id)
      base.merge!(
        "deal" => deal.attributes,
        "contact" => deal.contact.attributes
      )
    elsif event.entity_type == "Contact"
      contact = Contact.find(event.entity_id)
      base.merge!("contact" => contact.attributes)
    end
    base
  end

  def dispatch_action(action, event, context)
    case action["type"]
    when "deal.move_stage"
      deal = Deal.find(event.entity_id)
      stage = Stage.find_by!(account_id: deal.account_id, id: action.dig("args", "stage_id"))
      deal.update!(stage: stage)
    when "deal.add_tag"
      deal = Deal.find(event.entity_id)
      tag = Tag.find_or_create_by!(account_id: deal.account_id, name: action.dig("args", "name"))
      Tagging.find_or_create_by!(account_id: deal.account_id, tag:, taggable: deal)
    when "activity.create_task"
      parent = event.entity_type.constantize.find(event.entity_id)
      parent.activities.create!(
        account_id: parent.account_id,
        activity_type: "task",
        subject: action.dig("args", "subject"),
        due_at: Time.current + (action.dig("args", "due_in_minutes") || 60).minutes
      )
    when "webhook.post"
      WebhookDispatchJob.perform_later(event.id)
    else
      Rails.logger.info("Unknown action: #{action}")
    end
  end
end

# app/jobs/webhook_dispatch_job.rb
class WebhookDispatchJob < ApplicationJob
  queue_as :default
  def perform(event_id)
    event = DomainEvent.find(event_id)
    WebhookEndpoint.where(account_id: event.account_id, active: true).find_each do |wh|
      Faraday.post(wh.url) do |req|
        req.headers["Content-Type"] = "application/json"
        req.headers["X-CRM-Signature"] = OpenSSL::HMAC.hexdigest("SHA256", wh.secret.to_s, event.payload.to_json)
        req.body = {
          id: event.id,
          type: event.event_type,
          entity_type: event.entity_type,
          entity_id: event.entity_id,
          payload: event.payload,
          occurred_at: event.occurred_at
        }.to_json
      end
    end
  end
end
```

---

## 5) Controllers (classic REST + JSON)
```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include Pundit::Authorization
  before_action :authenticate_user!
  before_action :set_current_account

  private
  def set_current_account
    # Example: derive from request subdomain (acme.myapp.com)
    acc = Account.find_by!(subdomain: request.subdomains.first)
    Current.account = acc
    Current.user = current_user
    raise ActiveRecord::RecordNotFound unless current_user.account_id == acc.id
  end
end

# app/controllers/contacts_controller.rb
class ContactsController < ApplicationController
  def index
    @contacts = Contact.where(account_id: Current.account.id).order(created_at: :desc).page(params[:page])
    respond_to do |fmt|
      fmt.html
      fmt.json { render json: @contacts }
    end
  end
  def new; @contact = Contact.new end
  def create
    @contact = Contact.new(contact_params.merge(account_id: Current.account.id))
    authorize @contact
    if @contact.save
      redirect_to @contact, notice: "Contact created"
    else
      render :new
    end
  end
  def show
    @contact = Contact.find(params[:id])
    authorize @contact
  end
  def update
    @contact = Contact.find(params[:id])
    authorize @contact
    if @contact.update(contact_params)
      redirect_to @contact, notice: "Updated"
    else
      render :show
    end
  end
  private
  def contact_params
    params.require(:contact).permit(:first_name, :last_name, :email, :phone, :company_id, custom_fields: {})
  end
end

# app/controllers/deals_controller.rb
class DealsController < ApplicationController
  def index
    @deals = Deal.where(account_id: Current.account.id).includes(:contact, :stage, :pipeline).order(updated_at: :desc)
  end
  def create
    @deal = Deal.new(deal_params.merge(account_id: Current.account.id))
    authorize @deal
    if @deal.save
      redirect_to @deal
    else
      render :new
    end
  end
  def move_stage
    @deal = Deal.find(params[:id])
    authorize @deal
    new_stage = Stage.find(params[:stage_id])
    @deal.update!(stage: new_stage)
    redirect_to @deal, notice: "Stage updated"
  end
  private
  def deal_params
    params.require(:deal).permit(:title, :contact_id, :company_id, :pipeline_id, :stage_id, :amount, :expected_close_on, :status, custom_fields: {})
  end
end

# app/controllers/automations_controller.rb
class AutomationsController < ApplicationController
  def index
    @automations = Automation.where(account_id: Current.account.id)
  end
  def create
    @automation = Automation.new(automation_params.merge(account_id: Current.account.id))
    authorize @automation
    if @automation.save
      redirect_to automations_path, notice: "Automation created"
    else
      render :new
    end
  end
  private
  def automation_params
    params.require(:automation).permit(:name, :active, :trigger_event, condition_json: {}, actions_json: [])
  end
end
```

---

## 6) Routes (REST + minimal extras)
```ruby
# config/routes.rb
Rails.application.routes.draw do
  devise_for :users
  resources :contacts do
    resources :activities, only: [:create]
  end
  resources :companies
  resources :pipelines do
    resources :stages
  end
  resources :deals do
    member { post :move_stage }
    resources :activities, only: [:create]
  end
  resources :tags, only: [:index, :create, :destroy]
  resources :automations
  resources :webhook_endpoints

  namespace :api do
    namespace :v1 do
      resources :contacts
      resources :deals
      post "events", to: "events#create" # optional inbound events
    end
  end
  root "deals#index"
end
```

---

## 7) Views (ERB + Turbo)
*Keep it simple for MVP; enhance with Stimulus later.*

```
# app/views/deals/index.html.erb
<h1>Deals</h1>
<table>
  <thead><tr><th>Title</th><th>Contact</th><th>Stage</th><th>Amount</th></tr></thead>
  <tbody>
    <% @deals.each do |d| %>
      <tr>
        <td><%= link_to d.title, d %></td>
        <td><%= d.contact.full_name %></td>
        <td><%= d.stage.name %></td>
        <td><%= number_to_currency(d.amount) if d.amount %></td>
      </tr>
    <% end %>
  </tbody>
</table>
```

---

## 8) Policies (Pundit)
```ruby
# app/policies/application_policy.rb
class ApplicationPolicy
  attr_reader :user, :record
  def initialize(user, record) = @user, @record = user, record
  def admin? = user.role_admin? || user.role_owner?
  def index? = true
  def show? = record.account_id == user.account_id
  def create? = admin?
  def update? = show? && admin?
  def destroy? = admin?

  class Scope
    def initialize(user, scope) = @user, @scope = user, scope
    def resolve = @scope.where(account_id: @user.account_id)
  end
end
```

---

## 9) Seed data
```ruby
# db/seeds.rb
acc = Account.find_or_create_by!(name: "Acme Inc", subdomain: "acme")
user = User.find_or_create_by!(account: acc, email: "owner@acme.test") do |u|
  u.password = "password123"; u.role = :owner; u.name = "Owner"
end

sales = Pipeline.find_or_create_by!(account: acc, name: "Sales")
qual = Stage.find_or_create_by!(account: acc, pipeline: sales, name: "Qualification", position: 1)
prop = Stage.find_or_create_by!(account: acc, pipeline: sales, name: "Proposal", position: 2)
won  = Stage.find_or_create_by!(account: acc, pipeline: sales, name: "Won", position: 3)

c = Contact.create!(account: acc, first_name: "Jane", last_name: "Doe", email: "jane@example.com")
Deal.create!(account: acc, contact: c, pipeline: sales, stage: qual, title: "CRM Core MVP", amount: 5000)

Automation.create!(
  account: acc,
  name: "Move to Proposal when amount >= 5000",
  trigger_event: "deal.created",
  condition_json: { ">=" => [ {"var" => "deal.amount"}, 5000 ] },
  actions_json: [ { "type" => "deal.move_stage", "args" => { "stage_id" => prop.id } } ]
)
```

---

## 10) Gemfile (relevant bits)
```ruby
# Gemfile
ruby "3.2.2"

# Auth, policy, jobs, HTTP
gem "devise"
gem "pundit"
gem "sidekiq"
gem "faraday"

# Postgres niceties
gem "pg"

# Frontend defaults
gem "turbo-rails"

# Testing (optional)
group :development, :test do
  gem "rspec-rails"
  gem "factory_bot_rails"
  gem "faker"
end
```

---

## 11) Multi-tenancy guardrails
- **Controller guard**: ensure `Current.account` is set; reject cross-account access.
- **Policy Scope**: always filter by `account_id`.
- **Service methods**: require `account:` explicitly.
- Avoid `default_scope`; prefer explicit scopes or policies to prevent surprises.

---

## 12) Extensibility hooks
- New module (e.g., Forms) can:
  - Create its own tables keyed by `account_id`.
  - Subscribe to core via **DomainEvent** (or read `domain_events` tail) and **Automations**.
  - Contribute actions by extending `AutomationRunnerJob#dispatch_action` or via a registry.
- Promote frequently-queried JSONB keys to **generated columns** later.

---

## 13) API quickstart (for integrations)
```http
POST /api/v1/contacts
{
  "contact": {"first_name":"Ana","last_name":"Liu","email":"ana@x.io"}
}

POST /api/v1/deals
{
  "deal": {"title":"Loan Onboarding","contact_id":"...","pipeline_id":"...","stage_id":"...","amount":12000}
}
```
Auth with an account-scoped `ApiKey` (Bearer raw token at creation time).

---

## 14) Hardening checklist (MVP+)
- Rate-limit API endpoints per ApiKey.
- Add request signing for inbound webhooks.
- Audit log for data changes (PaperTrail if desired).
- Background mailer for Activities of type `email`.
- Indexes for frequent filters (e.g., `deals(status)`, `activities(due_at)`).
- Basic full-text search on contacts/deals titles.

---

## 15) Quick scaffold commands (optional helpers)
```bash
rails g model Account name subdomain:uniq --uuid
rails g devise User --uuid
rails g model Company account:references{uuid} name custom_fields:jsonb --uuid
rails g model Contact account:references{uuid} company:references{uuid} first_name last_name email phone custom_fields:jsonb --uuid
rails g model Pipeline account:references{uuid} name --uuid
rails g model Stage account:references{uuid} pipeline:references{uuid} name position:integer --uuid
rails g model Deal account:references{uuid} contact:references{uuid} company:references{uuid} pipeline:references{uuid} stage:references{uuid} title status amount:decimal expected_close_on:date custom_fields:jsonb --uuid
rails g model Activity account:references{uuid} activity_type subject body:text due_at:datetime completed:boolean actor:references{uuid} subjectable:references{uuid}{polymorphic} metadata:jsonb --uuid
rails g model Tag account:references{uuid} name --uuid
rails g model Tagging account:references{uuid} tag:references{uuid} taggable:references{uuid}{polymorphic} --uuid
rails g model DomainEvent account:references{uuid} event_type entity_type entity_id:uuid payload:jsonb occurred_at:datetime --uuid
rails g model Automation account:references{uuid} name active:boolean trigger_event condition_json:jsonb actions_json:jsonb --uuid
rails g model ApiKey account:references{uuid} name token_digest last_used_at:datetime active:boolean --uuid
rails g model WebhookEndpoint account:references{uuid} name url secret active:boolean --uuid
```

---

## 16) What you get out of the box
- Contacts, Companies, Deals, Pipelines/Stages, Activities, Tags
- Event log + simple Automation engine
- Webhooks + API keys
- Solid tenancy and RBAC hooks (Devise + Pundit)
- JSONB for flexible custom fields

From here, you can plug in **Forms** and **Products** as separate engines or namespaces, consuming core events and emitting their own.

