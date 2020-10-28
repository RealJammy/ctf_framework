"""Add flag table

Revision ID: 425aef1f1174
Revises: 55ae6873facd
Create Date: 2020-10-28 09:50:16.982181

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '425aef1f1174'
down_revision = '55ae6873facd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('flag',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('hash', sa.String(length=64), nullable=True),
    sa.Column('points', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('association',
    sa.Column('team_id', sa.Integer(), nullable=True),
    sa.Column('flag_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['flag_id'], ['flag.id'], ),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('association')
    op.drop_table('flag')
    # ### end Alembic commands ###
