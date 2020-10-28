"""empty message

Revision ID: 29b1962b94d8
Revises: d372a380d6e6
Create Date: 2020-10-28 10:25:39.161872

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '29b1962b94d8'
down_revision = 'd372a380d6e6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('team', sa.Column('last_flag', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('team', 'last_flag')
    # ### end Alembic commands ###
