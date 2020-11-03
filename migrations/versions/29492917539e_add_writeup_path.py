"""add writeup path

Revision ID: 29492917539e
Revises: d292ea75fc9e
Create Date: 2020-11-03 16:26:27.332024

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '29492917539e'
down_revision = 'd292ea75fc9e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('challenge', sa.Column('writeup_path', sa.String(length=256), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('challenge', 'writeup_path')
    # ### end Alembic commands ###