"""empty message

Revision ID: 55ae6873facd
Revises: 
Create Date: 2020-10-27 20:30:45.138983

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '55ae6873facd'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('team',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=64), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('score', sa.Integer(), nullable=True),
    sa.Column('about_us', sa.String(length=400), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_team_email'), 'team', ['email'], unique=True)
    op.create_index(op.f('ix_team_username'), 'team', ['username'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_team_username'), table_name='team')
    op.drop_index(op.f('ix_team_email'), table_name='team')
    op.drop_table('team')
    # ### end Alembic commands ###