"""
Domain Reputation Management API Router.

Provides endpoints for managing the domain allowlist/denylist.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.logging_utils import log_domain_reputation_update
from app.models_legacy import DomainReputation
from app.schemas_legacy import DomainReputationCreate, DomainReputationRead

router = APIRouter(prefix="/api/domains", tags=["Domain Reputation"])


@router.post(
    "",
    response_model=DomainReputationRead,
    summary="Create or Update Domain Reputation",
    description="""
    Add or update a domain's reputation in the database.
    
    Use this endpoint to:
    - Add official domains to the allowlist (is_official=true)
    - Add known malicious domains to the denylist (is_denied=true)
    - Update existing domain reputation
    
    This operation is idempotent - if the domain already exists, it will be updated.
    
    Security Note:
    - Official domains receive low risk scores automatically
    - Denied domains receive very high risk scores
    - Changes are logged for audit purposes
    """
)
async def create_or_update_domain(
    domain: DomainReputationCreate,
    db: AsyncSession = Depends(get_db)
) -> DomainReputationRead:
    """
    Create or update domain reputation.
    
    This is an idempotent operation - if the domain already exists,
    its reputation will be updated.
    
    Args:
        domain: Domain reputation data
        db: Database session
        
    Returns:
        Created or updated domain reputation
    """
    # Normalize host
    host_lower = domain.host.lower().strip()
    
    # Check if domain already exists
    result = await db.execute(
        select(DomainReputation).where(DomainReputation.host == host_lower)
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Update existing record
        existing.is_official = domain.is_official
        existing.is_denied = domain.is_denied
        existing.note = domain.note
        
        await db.commit()
        await db.refresh(existing)
        
        log_domain_reputation_update(
            host=host_lower,
            is_official=domain.is_official,
            is_denied=domain.is_denied,
            action="updated"
        )
        
        return DomainReputationRead.model_validate(existing)
    else:
        # Create new record
        new_reputation = DomainReputation(
            host=host_lower,
            is_official=domain.is_official,
            is_denied=domain.is_denied,
            note=domain.note
        )
        
        db.add(new_reputation)
        await db.commit()
        await db.refresh(new_reputation)
        
        log_domain_reputation_update(
            host=host_lower,
            is_official=domain.is_official,
            is_denied=domain.is_denied,
            action="created"
        )
        
        return DomainReputationRead.model_validate(new_reputation)


@router.get(
    "/{host}",
    response_model=DomainReputationRead,
    summary="Get Domain Reputation",
    description="Retrieve reputation information for a specific domain."
)
async def get_domain_reputation(
    host: str,
    db: AsyncSession = Depends(get_db)
) -> DomainReputationRead:
    """
    Get reputation for a specific domain.
    
    Args:
        host: Domain to look up
        db: Database session
        
    Returns:
        Domain reputation information
        
    Raises:
        HTTPException: If domain not found
    """
    host_lower = host.lower().strip()
    
    result = await db.execute(
        select(DomainReputation).where(DomainReputation.host == host_lower)
    )
    reputation = result.scalar_one_or_none()
    
    if not reputation:
        raise HTTPException(
            status_code=404,
            detail=f"Domain '{host}' not found in reputation database"
        )
    
    return DomainReputationRead.model_validate(reputation)
