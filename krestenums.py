# key-rest-enums
#
# definition file
######################################################################
import enum

# Class and enumersations taken from KMIP standard
class ObjectType(enum.Enum):
    CERTIFICATE         = 0x00000001
    SYMMETRIC_KEY       = 0x00000002
    PUBLIC_KEY          = 0x00000003
    PRIVATE_KEY         = 0x00000004
    SPLIT_KEY           = 0x00000005
    TEMPLATE            = 0x00000006 
    SECRET_DATA         = 0x00000007
    OPAQUE_DATA         = 0x00000008
    PGP_KEY             = 0x00000009
    CERTIFICATE_REQUEST = 0x0000000A
    
class ObjectTypeName(enum.Enum):
    CERTIFICATE         = 'CERTIFICATE'
    SYMMETRIC_KEY       = 'SYMMETRIC KEY'
    PUBLIC_KEY          = 'PUBLIC_KEY'
    PRIVATE_KEY         = 'PRIVATE_KEY'
    SPLIT_KEY           = 'SPLIT_KEY'
    TEMPLATE            = 'TEMPLATE' 
    SECRET_DATA         = 'SECRET_DATA'
    OPAQUE_DATA         = 'OPAQUE_DATA'
    PGP_KEY             = 'PGP_KEY'
    CERTIFICATE_REQUEST = 'CERTIFICATE_REQUEST'
    
class CryptographicUsageMask(enum.Enum):
    # KMIP 1.0
    SIGN                = 0x00000001
    VERIFY              = 0x00000002
    ENCRYPT             = 0x00000004
    DECRYPT             = 0x00000008
    WRAP_KEY            = 0x00000010
    UNWRAP_KEY          = 0x00000020
    EXPORT              = 0x00000040
    MAC_GENERATE        = 0x00000080
    MAC_VERIFY          = 0x00000100
    DERIVE_KEY          = 0x00000200
    CONTENT_COMMITMENT  = 0x00000400
    KEY_AGREEMENT       = 0x00000800
    CERTIFICATE_SIGN    = 0x00001000
    CRL_SIGN            = 0x00002000
    GENERATE_CRYPTOGRAM = 0x00004000  # Designated '(Reserved)' in KMIP 2.0
    VALIDATE_CRYPTOGRAM = 0x00008000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_ENCRYPT   = 0x00010000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_DECRYPT   = 0x00020000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_WRAP      = 0x00040000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_UNWRAP    = 0x00080000  # Designated '(Reserved)' in KMIP 2.0
    # KMIP 2.0
    AUTHENTICATE        = 0x00100000
    UNRESTRICTED        = 0x00200000
    FPE_ENCRYPT         = 0x00400000
    FPE_DECRYPT         = 0x00800000    
    
class GKLMAttributeType(enum.Enum):
    UUID                        = 'uuid'
    INFORMATION                 = 'information'
    ALIAS                       = 'alias'
    KEY_ALGORITHM               = 'key algorithm'
    KEY_LENGTH                  = 'key length (in bits)'
    KEY_TYPE                    = 'key type'
    OWNER                       = 'owner'
    KEY_STORE_NAME              = 'key store name'
    KEY_STORE_UUID              = 'key store uuid'
    KEY_STATE                   = 'key state'
    ACTIVATION_DATE             = 'activation date'
    ARCHIVE_DATE                = 'archive date'
    COMPROMISE_DATE             = 'compromise date'
    CREATION_DATE               = 'creation date'
    EXPIRATION_DATE             = 'expiration date'
    DESTROY_DATE                = 'destroy date'
    KEY_GROUP_IDS               = 'key group ids'
    HASH_VALUE                  = 'hash value'
    USAGE                       = 'usage'
    CRYPTOGRAPHIC_USAGE_MASK    = 'Cryptographic Usage Mask'
    USAGE_LIMITS                = 'Usage Limits'
    OPERATIONAL_POLICY_NAME     = 'Operation Policy Name'
    PROCESS_START_DATE          = 'Process Start Date'
    PROTECT_STOP_DATE           = 'Protect Stop Date'
    DEACTIVATION_DATE           = 'Deactivation Date'
    CONTACT_INFORMATION         = 'Contact Information'
    REVOCATION_REASON           = 'Revocation Reason'
    NAME                        = 'Name'
    CRYPTOGRAPHIC_PARAMETERS    = 'Cryptographic Parameters'
    OBJECT_GROUP                = 'Object Group'
    LINK                        = 'Link'
    DIGEST                      = 'Digest'
    APPLICATION_SPECIFIC_INFORMATION = 'Application Specific Information'
    CUSTOM_ATTRIBUTES           = 'Custom Attributes'
    LAST_CHANGED_DATE           = 'Last Changed Date'
    COMPROMISE_OCCURANCE_DATE   = 'Compromise Occurence Date'
    LEASE_TIME                  = 'Lease Time'
    KEY_BLOCK                   = "KEY_BLOCK"
    KEY_MATERIAL                = "KEY_MATERIAL"
    KEY_FORMAT                  = "KEY_FORMAT"
    
class CMAttributeType(enum.Enum):
    ID                          = 'id'
    URI                         = 'uri'
    ACCOUNT                     = 'account'
    APPLICATION                 = 'application'
    DEV_ACCOUNT                 = 'devAccount'
    CREATED_AT                  = 'createdAt'
    NAME                        = 'name'
    UPDATED_AT                  = 'updatedAT'
    ACTIVATION_DATE             = 'activationDate'
    STATE                       = 'state'
    USAGE                       = 'usage'
    USAGE_MASK                  = 'usageMask'
    META                        = 'meta'
    OBJECT_TYPE                 = 'objectType'
    ALIASES                     = 'aliases'
    SHA1_FINGERPRINT            = 'sha1Fingerprint'
    SHA256_FINGERPRINT          = 'sha256Fingerprint'
    DEFAULT_IV                  = 'defaultIV'
    VERSION                     = 'version'
    ALGORITHM                   = 'algorithm'
    SIZE                        = 'size'
    UNEXPORTABLE                = 'unexportable'
    UNDELETEABLE                = 'undeletable'
    NEVER_EXPORTED              = 'neverExported'
    NEVER_EXPORTABLE            = 'neverExportable'
    EMPTY_MATERIAL              = 'emptyMaterial'
    UUID                        = 'uuid'
    MUID                        = 'muid'
    MATERIAL                    = 'material'
    FORMAT                      = 'format'
    OWNER_ID                    = 'ownerId'
    RESOURCES                   = 'resources'
    
class CMUserAttribute(enum.Enum):    
    NAME                        = 'name'
    NICKNAME                    = 'nickname'
    USER_ID                     = 'user_id'

        
class listOnlyOption(enum.Enum):
    NEITHER                     = 'NEITHER'
    SOURCE                      = 'SOURCE'
    DESTINATION                 = 'DESTINATION'
    BOTH                        = 'BOTH'
    
class NetAppAttribute(enum.Enum):
    NODEID                      = 'x-NETAPP-NodeId'
    CLUSTERNAME                 = 'x-NETAPP-ClusterName'
    VSERVERID                   = 'x-NETAPP-VserverId'
    
    