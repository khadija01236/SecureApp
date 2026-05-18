"""initial migration

Revision ID: 0001
Revises:
Create Date: 2026-05-18

"""
from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('password_hash', sa.String(length=256), nullable=False),
        sa.Column('totp_secret', sa.String(length=64), nullable=True),
        sa.Column('totp_enabled', sa.Boolean(), nullable=False),
        sa.Column('email_otp_enabled', sa.Boolean(), nullable=False),
        sa.Column('email_otp_code', sa.String(length=8), nullable=True),
        sa.Column('email_otp_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('backup_codes_json', sa.Text(), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_ip', sa.String(length=45), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_username', 'users', ['username'], unique=True)

    op.create_table(
        'login_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('event_type', sa.String(length=32), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=256), nullable=True),
        sa.Column('details', sa.String(length=256), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_login_events_timestamp', 'login_events', ['timestamp'], unique=False)


def downgrade():
    op.drop_index('ix_login_events_timestamp', table_name='login_events')
    op.drop_table('login_events')
    op.drop_index('ix_users_username', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
