"""phase3: auth, rbac, multi-tenancy, and audit logging

Revision ID: e5f66fb268d2
Revises: 1c524f57a183
Create Date: 2026-08-21 18:55:27.429377

This migration is NOT a straight autogenerate output -- it's hand-edited
to safely carry forward existing single-tenant data. Autogenerate wanted
to add asset/scan/report.organization_id as NOT NULL directly (which
fails on any table with existing rows) and to just drop org_profile
outright (which would silently discard whatever ASV/customer contact
info was already on file). Instead:

  1. Create the new auth/tenancy tables.
  2. Add organization_id as NULLABLE on asset/scan/report.
  3. Backfill: read the old org_profile 'customer' row (if any) into a
     new Organization row -- or synthesize a 'Default Organization' if
     none existed -- and point every existing asset/scan/report at it.
     Carry the old 'asv' row's data into the new single-row asv_profile
     table the same way.
  4. Only THEN tighten organization_id to NOT NULL, once every row is
     guaranteed to have a value.
  5. Drop the now-fully-migrated org_profile table.

No User accounts are created here -- that's a manual step
(`flask db upgrade` then visit /setup) since account creation needs a
real password, not a placeholder one written into a migration.
"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime


# revision identifiers, used by Alembic.
revision = 'e5f66fb268d2'
down_revision = '1c524f57a183'
branch_labels = None
depends_on = None


def upgrade():
    # --- 1. New tables -----------------------------------------------------
    op.create_table('asv_profile',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('company_name', sa.String(length=255), nullable=True),
        sa.Column('contact_name', sa.String(length=255), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=True),
        sa.Column('phone', sa.String(length=50), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=True),
        sa.Column('address', sa.Text(), nullable=True),
        sa.Column('url', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table('organization',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('contact_name', sa.String(length=255), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=True),
        sa.Column('phone', sa.String(length=50), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=True),
        sa.Column('address', sa.Text(), nullable=True),
        sa.Column('url', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('is_active_user', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organization.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_table('audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('entity_type', sa.String(length=50), nullable=True),
        sa.Column('entity_id', sa.Integer(), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organization.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # --- 2. organization_id as NULLABLE first -------------------------------
    with op.batch_alter_table('asset', schema=None) as batch_op:
        batch_op.add_column(sa.Column('organization_id', sa.Integer(), nullable=True))
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.add_column(sa.Column('organization_id', sa.Integer(), nullable=True))
    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.add_column(sa.Column('organization_id', sa.Integer(), nullable=True))

    # --- 3. Backfill ---------------------------------------------------------
    bind = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=bind, only=['asset', 'scan', 'report'])

    # org_profile may not exist at all if this is a brand-new install
    # jumping straight to head -- in that case there's nothing to carry
    # forward and no existing asset/scan/report rows to backfill either.
    inspector = sa.inspect(bind)
    has_org_profile = 'org_profile' in inspector.get_table_names()

    customer_row = None
    asv_row = None
    if has_org_profile:
        org_profile = sa.Table('org_profile', meta, autoload_with=bind)
        customer_row = bind.execute(
            sa.select(org_profile).where(org_profile.c.role == 'customer')
        ).fetchone()
        asv_row = bind.execute(
            sa.select(org_profile).where(org_profile.c.role == 'asv')
        ).fetchone()

    organization_table = sa.Table('organization', meta, autoload_with=bind)
    asv_profile_table = sa.Table('asv_profile', meta, autoload_with=bind)

    asset_table = meta.tables['asset']
    existing_asset_count = bind.execute(sa.select(sa.func.count()).select_from(asset_table)).scalar()

    # Only create a Default Organization if there's existing tenant data
    # (assets/scans/reports) that needs somewhere to land. A fresh install
    # with no prior data skips this -- the first real Organization gets
    # created through /admin/organizations after setup instead.
    if existing_asset_count and existing_asset_count > 0:
        org_name = (customer_row.company_name if customer_row and customer_row.company_name
                    else 'Default Organization')
        result = bind.execute(
            organization_table.insert().values(
                name=org_name,
                contact_name=customer_row.contact_name if customer_row else None,
                title=customer_row.title if customer_row else None,
                phone=customer_row.phone if customer_row else None,
                email=customer_row.email if customer_row else None,
                address=customer_row.address if customer_row else None,
                url=customer_row.url if customer_row else None,
                created_at=datetime.utcnow(),
            )
        )
        default_org_id = result.inserted_primary_key[0]

        for table_name in ('asset', 'scan', 'report'):
            t = meta.tables[table_name]
            bind.execute(t.update().values(organization_id=default_org_id))

    if asv_row:
        bind.execute(
            asv_profile_table.insert().values(
                company_name=asv_row.company_name,
                contact_name=asv_row.contact_name,
                title=asv_row.title,
                phone=asv_row.phone,
                email=asv_row.email,
                address=asv_row.address,
                url=asv_row.url,
            )
        )

    # --- 4. Now safe to enforce NOT NULL + FK (table is either fully
    # backfilled, or empty and safe to constrain directly) --------------------
    with op.batch_alter_table('asset', schema=None) as batch_op:
        batch_op.alter_column('organization_id', nullable=False)
        batch_op.create_foreign_key('fk_asset_organization_id', 'organization', ['organization_id'], ['id'])
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.alter_column('organization_id', nullable=False)
        batch_op.create_foreign_key('fk_report_organization_id', 'organization', ['organization_id'], ['id'])
    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.alter_column('organization_id', nullable=False)
        batch_op.create_foreign_key('fk_scan_organization_id', 'organization', ['organization_id'], ['id'])

    # --- 5. Drop the fully-migrated old table --------------------------------
    if has_org_profile:
        op.drop_table('org_profile')


def downgrade():
    # This downgrade is inherently lossy: User accounts, Organization
    # records beyond the first, and the audit trail cannot be
    # reconstructed into the old single-tenant shape. Best-effort: fold
    # the first Organization + the asv_profile row back into a 2-row
    # org_profile table so contact info isn't silently destroyed, then
    # drop everything else.
    bind = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=bind, only=['organization', 'asv_profile'])

    org_table = meta.tables.get('organization')
    asv_table = meta.tables.get('asv_profile')
    first_org = bind.execute(sa.select(org_table)).fetchone() if org_table is not None else None
    asv_row = bind.execute(sa.select(asv_table)).fetchone() if asv_table is not None else None

    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('organization_id')

    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('organization_id')

    with op.batch_alter_table('asset', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('organization_id')

    op.create_table('org_profile',
        sa.Column('id', sa.INTEGER(), nullable=False),
        sa.Column('role', sa.VARCHAR(length=20), nullable=False),
        sa.Column('company_name', sa.VARCHAR(length=255), nullable=True),
        sa.Column('contact_name', sa.VARCHAR(length=255), nullable=True),
        sa.Column('title', sa.VARCHAR(length=255), nullable=True),
        sa.Column('phone', sa.VARCHAR(length=50), nullable=True),
        sa.Column('email', sa.VARCHAR(length=255), nullable=True),
        sa.Column('address', sa.TEXT(), nullable=True),
        sa.Column('url', sa.VARCHAR(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('role')
    )

    new_meta = sa.MetaData()
    org_profile = sa.Table('org_profile', new_meta, autoload_with=bind)
    if asv_row:
        bind.execute(org_profile.insert().values(
            role='asv', company_name=asv_row.company_name, contact_name=asv_row.contact_name,
            title=asv_row.title, phone=asv_row.phone, email=asv_row.email,
            address=asv_row.address, url=asv_row.url,
        ))
    if first_org:
        bind.execute(org_profile.insert().values(
            role='customer', company_name=first_org.name, contact_name=first_org.contact_name,
            title=first_org.title, phone=first_org.phone, email=first_org.email,
            address=first_org.address, url=first_org.url,
        ))

    op.drop_table('audit_log')
    op.drop_table('user')
    op.drop_table('organization')
    op.drop_table('asv_profile')
