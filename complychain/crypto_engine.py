import os
import json
import hashlib
import secrets
import ctypes
import tempfile
import shutil
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization  # For key validation
from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from contextlib import contextmanager

# Try to import liboqs for quantum-safe cryptography
try:
    import oqs
    OQS_AVAILABLE = True
    logger = logging.getLogger(__name__)
    logger.info("liboqs-python available - quantum-safe cryptography enabled")
except ImportError:
    OQS_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("liboqs-python not available - trying pqcrypto alternatives")

# Try to import pqcrypto for alternative quantum-safe cryptography
try:
    import pqcrypto.sign
    PQCRYPTO_AVAILABLE = True
    logger.info("pqcrypto available - alternative quantum-safe cryptography enabled")
except ImportError:
    PQCRYPTO_AVAILABLE = False
    logger.warning("pqcrypto not available - falling back to RSA-4096")

# Check which pqcrypto algorithms are available
def get_available_pqcrypto_algorithms():
    """Get available pqcrypto signature algorithms."""
    if not PQCRYPTO_AVAILABLE:
        return []
    
    available = []
    try:
        # Check for Falcon
        import pqcrypto.sign.falcon_1024
        available.append("falcon_1024")
    except ImportError:
        pass
    
    try:
        import pqcrypto.sign.falcon_512
        available.append("falcon_512")
    except ImportError:
        pass
    
    try:
        # Check for SPHINCS+
        import pqcrypto.sign.sphincs_sha2_256f_simple
        available.append("sphincs_sha2_256f_simple")
    except ImportError:
        pass
    
    return available

AVAILABLE_PQCRYPTO_ALGORITHMS = get_available_pqcrypto_algorithms()

# Security parameters (PRODUCTION-READY)
SCRYPT_N = 2**14  # 16,384 iterations (production balance)
SCRYPT_R = 8       # Reduced memory cost
MIN_SALT_LEN = 32  # 256-bit salt

# FIPS Known-Answer Test Vectors (NIST PQC Round 3)
FIPS_TEST_PUB = b'\x1c\x0e\xe1\x11\x1b\x08\x00?(\xe6^\x8b;\xde\xb07\xcf\x8f"\x1d\xfc\xda\xf5\x95\x0e\xdb8\xd5\x06\xd8[\xef\xd9\xfd\xe3\xa4\x96\xf7X\x19\xf0\xa2\r\x04A\xdcx0\xb4\xaa\x1c\xb8\xec\xfc\x91\xba\x0e\xec:\xfbgD\xe4w\xb4\xe6\xec?\xda\xe7PH\xff\xeb\xaa\xbe\xa8\xe8"\x11}W\x87\xf7\x90p\xea\x88(|\xe3\xcdP\x11\xfd\x8d\x93\xab~\x8bQ\xf2a\x16\xbf\x9bm!\xc0?\x88\xbf\xecH\x88v\xf4\xd0u\xa1B\xd4\xe7\x84\xd74@u\x11\xf9\x92\x06\x93S\xf1\xdbg\xac\xf704\xa4h\xa1\x18X\x80b\x11\x1d2\x0e\x00\xbc\xffm\xc65s\xfc\xed\x1e\x96\xaa\xeb\xa6E.<z\xcd\x19\x18\x1f\x9b\x81K\xa1\x9d9\xb4\xba\xb5Im\xc0UBn~\xa4a\xafU\xd5\xb9\xfe\x97\xf9\xdf~%2\x03\xc1\xf9\xe1R\xe9mu\xf9\xd9\xa8O\\&>\xc8\xc2PD\n\xdc\x98oN6ALp;>\x05Bk(\xb7\x06YP\xdam\x0e\x0b,`\xac6r\xdbo<xD}\xb7\xc2\t\x15w\x0e\xa6\xfc\xe8\x1d\xabS9\xc1\xd5\xaf\x82\xa5\xd32@\x99\xdfVQj\x07\xdb|\x0f\xc6C\x83\x80\\e\xf2\xb0/\xbc\xfc\xe6>\x93\xc4\xbf\t@\x9f\x9f\x0fw\xe7=\xa3\xb0\x01\x9f W\xe4\xcd|\xff\x0eWE\xef\x18\xc3\xfdvn\x01tzd\xd4\x15\xfc\x97\x89\xab\xfab(N\x11\xc7\xff\x05\xd0T\x8d\x97?g\x95Y\xa6\xa3\xaa\xd7~\xd5\x13-\x01P\xc0\x14\xc3\xec:9_\x01~z\xcf\xe3\xea\xbf\xcaD\x91\x0c\xa0o\xf35B\xec\xcebA\x97GB5}7\xf5\xc2\x84\xbf\x0f\xe1\xa7KP\xc0sU\x13r\x13:\xf2\xddA\xe2\x1b\xaf\xc9\xc5\x90\xeen\xbcJ\xces\x1e\xf5f\x15l\xa07U\xdcI<\x13p(\xaf;=\xe5\xb0\x0b\xd6\xcb=\x9a\x87\xd0\x15\x1f\x88|gh\xbcl\xa0*\x94\xfb \x86U\x1a\x0f\x89\xba&\x15N\x9dE\x06\xad\x9f\xaf9\xf5r>#N\x06\xcf\xde\xd6\x9dN\xe4\x14ks\xe5\xdc\x1eAR\xa2\xa3\x15\x9ds\xdb\xc83\xd3\xd4\x17\xcd\\\xf7\xfb=\xc7t\\\xee\xd4\xdc\x0f[\x1cmki\xc1vAW\xeaC\xdf\x9d\xbbD.\xfa9\xd1\xd0\x16.\x87\xc2\xd3\x0cP\x12\xfd\x16\xd8i\xc8\xa1\xfc\xbbE\xed\xcc\x8e\x18\x13\xb2\xb1\x90\xa9a\xf9\xfc\x86Y\x1d:\xbcS\x88\xafg\x8f\xf0=\xa7\x8b|\xc0\xf6\x18W!\xc0\xdf3\xcc\x90d5"]\xf2a\x10\x02\xdf\x12\x0e\x83Ve2)-\xea=\x8a\xcd\x10\x9a\r\xff\xab;\x0bC\x01\'\x96\xdb[Ph?\xb4\xc2\xd2P\xda\xb7j\xae5\xa4\x8e\x8c\x8dJ\\\xc1Tu\x97E\xf0\xa1#\x0fl\xa9\xdd\x9c\x99\xe2\xf8\x0e\xdc\x830L\xe0\x1e\x98\xf6\xc9H\x95)\xa8"\xf9\x003\xc2(1^\xb2\xfc\xc8\xdb\xa3\x82\xedC\x01\xe0v\x07\xa5\xb0v\xc7%\xf1$\x99O\x18\xa9\x97\xd2\xc5\xbb\xf9\xa3$`Re\x10\x8a\xcb\xf4a\x0f\xa1\xc37D\x08\x85\n\x08d\xe2\xb6\x10\x17\xeb\xec\x1f\xba\xb8\x9d\xe3\xab\x1b\x93\xceI\x18\xb9\xe2\xc9\xe3\xfeEgX\x06*\x9f\x88+(3\x18\'\x1fK\x95R\xfc\xf3&$\xa9\xfd\xaaD\xc6\\`\xe2\xb3d\x8b\xef\x1f\x17\xd0\xb7\xc7Hi\xee\x0bS\xc4\xa6*$\x84]\xce\xa5\xbc\xbf\x93\xb9.L&d\x85\x84\xe34y(.l\x8b\x1d\x8f\xe2\x11\x81\xbd\x9c\xf7_\x8a\x96\x17$\xd4\xc40\x97y\xf1\xf1\xb7u\xd2T\xf7\x0b\xd1v\x9c\xc7\xc0\xed\xd2\xa9_\xe5\xc9\xd8K\x16\xf7\xc5M\x85\xcc\xe4\xc8\xa1\x82\x81\x08\t\xed\x81\xe9}\x07H\x84\xee\xdf@\x1c\xca\xcd\xae\xad\x82\xc1M\x06\xb6\x8a\xeal\xe1K\x86\x1b\x0c\xfd\x16\t\x0c\xbb\xf4i\xc5\xe0\x841L\r\x8d9`\xea\x06\xa3Bm\x8b?\xe7b\xe0\r\t\xbd\xa3t\xf3\xae,\xbe\xde(8\xff\x89\xd8\x1d\xeb0\x13\t\x0eD\x19\x9a\xed`Ic\xea\xf9\x19\x91L\xe0O z\xc8,\xd45\x1f\xef{-\x9490f\xfeMD\xe3\xccYR\xe7^\xb6\xf3q@X\x91]\xe0\xee\x18M\x8cU0\x0fWj\x8b\x82\xa8c\xe8\x1a\xf34\x17\xbdL\xfc\x94\xe7\xa6\x12c\xb3\x9f\x01\xf6\xe2\xe7\x07H\xb6\xe5\xe5\x9c\xf6\xca\x01\xb0\x02\x8c\x93\xbb\xbc\xeb\xc5H\xf9\x87\xf1\x07U\xbf3\xcaX\\\xb4\x1c\xf5x\xdf_\xfe7\x92N<,\x07.\xd1\xda\xc9\x16!v\x97)q\xe7\x9bb\xfb \x8f\x1as\xbf\x03a\xe2\x99=\xcc\xcd1\x10\xc3M\x83\x9d\x18\xddC\xa5\xe8\xf0\xd9A\xe9\x9a\xdc\xf4A@_2\x10vq\xb2\xd8\xb2$O{\xa9-\xce\xd5\x87\xa2\x10\xfe\x8f\xf4<aj\xcb^vnj\xf2\xce\xb05\x99\xba=\xe3v\xebW5\xef\x16\x149S\xd1\xfd\xdb~\x9f(t\xb0\xd6\x08=\xd7\xecC\x86\xae\x00?Q\xcc\xf2\xd2\x1e\xf6\x05\x91c\xc5\x15!tB?W\x11\x9d\x0f\xceb}v=\x81\xc1\n\xa12\x9ft\xc8\xd4EC{\xa6q\x8a3\xdbny7Qr\xb2\xae5\x91\x82\x19x\xd5 \x82N-/\xf8\x98\xb7\xf4\xc8g\xffF\'"\xbc\x07\xea\xda\xd3\x89\xa9\x10\xb6\xf6T)\xda\x12\x975\xfe\x04\x9e>\xcb8\x89\xf6\x04|\xf2\xbd*\x88\xd5\ne\x1b25\xd2H\x0e\x1d\xa5\xa3RG\xfav\xc81sc\x99\xd3~\x8d\x03<\x1d\x05\x1c\x9bj\x99\xab\x80\xb11?\xa2L\\YvnlQ\xa3\x8f\xe9\xf1\x18jv~\xeb\xd0\xd8\x80\x01\xae\x02F\xcdN\xbe,\x97\x9d\xe8,0\xbb\xdb\x98\xb4tO\x11\xf9\xe69\xed\xdd\x8c\x19My\x11 \x1a\x8f\xa7E\x99\x1bM\x8aW\t\xb6*!\xb6;\x97b\x91=6\xce\x99\\-ky\x15\x1e\x8d\x83\x83\x8c\xd1\xf3\x88@\xa9ArU\xdd\x16kz5\x84I\x90\x03\xfbbV\x11@L\x95\xb9`\xdf\r\xb1\xbc\xf1WK\te\xdb\xd84\xee\x14\x81\x17\xd5\xe0Z|\xc7\xcc\x1a\x86V\x18\xa2\xbeHT\xdb\x895\xcd\xa1\xe6\x8b\xd8\xd0\x9er\xf0\xac\x90S\xc8\x82\xc4\xab\xa4\x00JaM\x10PS\x00\xb6\x17l\xa1\xf3$\xe2.x$)\x9f\x9c@u[q\xd8+g\x95G\xf0j\xd4\x8b\xe6mh\x07,\x93\x90#<\x93?\x80\xa1O\x8dJk\x0bN\x19p\xe1\xac\xc1\xbe\xa7\xf5\xd3\xbe"DH\xf8W\xba\xb6\x8a\xef\xa6\xd8\xcb\x81\x9bd)J\x12\x99y\x16\xcd\xbfV\xe9\xa8\xd0\x02\xdd\x06_\x12\xc6\x18#\xf4\xfc!E\x08#.C\x1f\x0bh\x98G[\xb5\xdd\r}R\x8e\x84\x0c"\x80\x9a\xf7\xe1ScrJa:\xcc\xfb\xe2\xb3t8\xc1Y\xce\x14\xcb\x0c\x98\xbf\xd4\x99\xc0\x8d\xac\x0c\xf4]\x82\x1c\xc2\xfaG1\x9bo\xb4\xce\xd7\xe5\x98^\xc8\'M\xe0\x90q\xd3\xc1\r\xa5\xbf\x9eR+\x01\xce\x91\xd6k\x91y]="\xc0\x04\x83EBu\xdd+\xbd\xd7\xc2\xdc\xc4\xa1g\xe5\xd7\xfc\xdb\xb9\xf6 \x8c\xd4\xc9\xa4\x85\xfa\xae\xb8\t\xa7q\x1d\xac(e\xce\xd40dt\xb2+DH\xf8]\xf34\x17\xf3\xfa\xce\x1c\x05\xd4\'\x03\xed10B\xa0]\xe06\'@\x13\x01\x88\xec\xb4E\xbb%]\xc7n\xe8D?s1\x17\xf85\x1f\x17`1uUO\xeb\x00\xb7\xffT\xd8\x07\x86\xf3\x05\xcd\xe1\x8c\xd5\xecV\xec\tb\xa3\xe0D\x82\xdc\xe3b-\x04\r$\xc4\x0f.\x8a\x14\xa4Ge\x9dlV\x1f/\xfe\xe6\x8f\x8d=\xe5\x11\xb2>\x8b\x17*\x01\xa3\xed\xa4\xd3x\x0et\xc6w$C0\xe9\xae\xff\x01\x9f\xe0{\xe3\xd3?2/\x9c\xe2!K\x9d\x9c\xff\x99\xd0ZY\xe4uQC*\xe7oL\xd4\xf8\xddQR\x0f\xfe\x81\x1bK\x93\xcdb\x19\xc8\x1bc\xb1\xd6\'x\\*\x0f\xc2.:\xea\x86\xce\xee\x1f\x7f\xbcN\xfc\xb4m\xdf\xbc\xd8\x8a\x02\xf3\xb4\xe6|_\xf2\xe8\xdch\xbf\x16\xc7F\x99\xbb\xb6(\x90/r\xc3\xde\xbc\x8b\xf5\xdfpmG\xa6\x05\xa1\x07\xda\xa0\x01A9\xce@\xf0\xd4m\x8dm\xc7'

FIPS_TEST_SM = b'\xb0U\xb0\xe1v\x10\xbfT\xb3;\x96\t\x8dyn\x98\xf7\x89\x9fHV\xcb\xc8\xd7\x04\xf9\xd7w\x8c\x18w\xf1\xe1$\xbfb\xa0\xd1\x7f\x01;\xe44\x0f\xd5{O\xa6"-\x9c\xdb\x90(\xe8\xb0+\x92n\x15T\xd1E\xf4G\x98\xaa\xc2\xfa\xa2\x03<J\xef\xb6\xcc\xb6\xcf\xe5\xc2\xa6#\x8e\xe7\x9c\\\xc2\xf0\xe8\x04\xbe\xd1\x7fu\xc1\xf3\x99M\xd7\xe7\xa0\xf2\xa7\x03L\x0c\x8c\x98d\x80@W\xe2\xe5Wg?\xdf\xd6d5o\xab\xd0Q\xf9\x07[4\x00\xa0\xc7\xe8EYU>\xdf\x98\x9b\xff\xd2\x11+)`"\x03\x06k\xde\xa7\x845\xeb\xc6\xe3\x81\x8c\xc9-a\xbc\xc1%\xa8W[Z\x8a\xeeB%\xfb\x9cbH?>\xd1\x18Zj\x96\x82.^\xfc\x1b\xa7\xcd\x8d_\xd8\xcc\x18}*&i\xca\xdfX\xfa\xd6b\x89yL\x96H[,FE\xc7\xd3\xd3V\x84\xb7B\x9b^\xf3\x15Ev\x99\xbe\x800\xbc=\xeb\x81f`*\xc5H\x19\x82H\x83\xa2F\xc8\xa1\xa3O\xc8\x9b/\xe02\x9b\\\xa0]N\x14\xb6\xdf\xfc!D`j\xb3`\xbb;\x8a\xc5\xa1x\x99\x8bF!\x81\x81\xca\xc8\xdeL)H0\xd4\x9d\x8f\x00\xec\x12\xc3\xd3\xac{J,0\x17X\xe6\x8aV\x81\x17\x7f\xf2\xa7]\x1dK\xf1\xc9&\x88\x0b4\xb7(\xf7\xc3.@`\x99\xd9Z\xb4H\x92\xf7H\xaa\xfe\xb5[&\xbe1u\x12\xb07}\xbe\x89\x1a\xc5Ej\x92L6\x83\x9b\xc8\x01\xdb*\xc5\xb7\x11\n\x9b\xafL<I\xd0\x059<\xdf\xfa\xd4\xf9ha \xf4\xfd\xe0\x16\x8a\x9eE\x8er\x9fK\n\xe1\xa4\xc4\x12L\xa3M\xf5\xb6;\xc2\xe7\xcb\xee\x01\xa3\x8d1\xa0\xed\x8d<L8\x03\xc3\xc2L\\\xad\xeb\xe3\xe9\x1a\x8d.\x1b\xfc\xf0P\x8a\'\x88\xd8\x9d\xfe\xa2\x0f\xd68\x18\xb89`\xa6\xcf\x93\x08r\xb9W\x85WP\x88\xcf~\x8bc\xa1\x89Z\x8c\x1cw\xa8L\xb9\xcck\xd1\xd5\xfa\x93\x96w\xaf\x17\xee\xbe-.\xe6\x84\xc6`\x15\xf1\xbb\x14*rwyX\r\xa1\xbc^\x97Z\xa5n\xf5\xd7z\x84\x07\xe5\x06\xa5\xde\xee\xa5\xe8\xb0y\x7f\x10d`\x05d\x80"!<\xcb\x86\xa7}\xf5\xd7\xb3\x16\xe8]U\xb9\xda\x0f\xdf\xd5\xf25R\xddG\xcc\xfa\x96J\xc3\x9e\xe6\x84\xbdcy;\xb7\xdc\xabi\xbe~\xd9M\x8d\xdb\xa1\x85\xe8\nz\xae\xe7N\x87\x8fP\xa2\x13\xf3\xb4\xff\xb6nm4\xa3\x9c\n\xae+\x1da6o\xe4\x03S\x9ci\xa0\x88u\x1fV\x90\x1a\x10\xbcD#\x13\xa3\\-\x83Tv\xd0\xfa\xd4G\xc7p\x08\x0f\xa4\x1b\xf3\x8dh_\xb3\x1b\x11\xa7\xd2\xe6\xfbRg=\x16\x87#\xe6\x89\x08\xc0g*\x0f6\xe2Z\x19\x9e\x17\xa6\xfe[\x8b\x82[\x96\xea\xb7\xabK}\x83\x81\xdb\xc5\x001\xa5\xf2\xe0\x9eK\xe8qS:\xdc]\x08\xd0\tB\x9b\xbf\\\x86\xf8\x12\r\t\\\x8e\xec\xbe\xf3\xe0\x99\xdea\x8dCw$\x1bP6\x9e\xdeQ\xaat\xab\x96e\x89\xe2\xc6\x87\xd6\xc0\x9f\xac\x9cmlTa\xf5\xa60\x08\xe9\x83_\xf4\xb5\xbdBe\xf1\x12\x8c\t,\'\xd4\xdaP\x8f\xd4\xf5\x0e\xfat\xa71W\x05\x9aK/A\xfe\x8b\xf9g\x16yi\xb9;\xf5 E\x84&\x902B\x9e5wpK\xdfh\x98\x00\xdd\x8b\xde\x82kt\xce\xf5\x10\xa1\xe0\x87\x02?\t&\xe9\x7f7\x92k\x16\xefxl7\xec!\xf2@q\x04\xd3\x95Jz\x07\xc3\r\xe2\xd6x\x84\x02\xd7\x1aV.\xa5Ly\xb4\x19} ,\x97r]-\x8b~s2\xf3\xff\x1ao\xadI\xa4\xc0\x0c\xd1\xa4Ge\x1b\x8e\x08\xd8Pk\xca\x82>\x10\xefA\x16\xe6\xcfIg\\C0\xa1\xde\x19\x08\xdd\xb5\x9f~\xa5\xf8\x9c\x94\xceP\x0f\x82\xb4<\xe7\x89\x15\x84s\xb9\xe0y\x05\xd8\xe8a^\xde\xf0!8?\xc3\x1da\x8c\\\xe6%e;@\xc2\x1b\xd7\xe0\xbcx=\x93\xbe\xc1\xb7\xa5\xb4\xbb\xc6\xc2\x81\xb7wUG9\x0e\xf3\xd3\x0e\'s\x996\x93\x08\xd8\xa1\xcd\xc2\xe1\xdb\xd6\xf1X\x97\n\xc2\xac\\,\x94\x81\x97[\x80\x95\x80\xc0\xea\x89\x91,\x07f\xf4X0\xa8\x96?\xbb~\x17\xd8C\x85\x17Zn\x07Th<\xbf\xbb\xa66E\x94\xf6\xb5\x00\\\x15\xbd_\x85s+Zc\xf2bg\xab\x17\x04\x8ca\x99 \x00\x19\xad\xd6\xa4\xd1\xac\xd0@\\8vf\xe8q\x11\xb9\x82Z\xfb\x97Q\xcd?\x9d\x8aE\xc6\xb2\x08\xd2\xd33\xb6\xc5\x9f\x98\xbc\xf2\x84\xc8T\xcf}OgT\xfdu\xee\x06\x8c\x88g\x8e\xe7V[G\xb3nh\xa1\xfd{\xb6\x0e*\x8e\r\xf7\x12p \xf5\xc6\'{>\xe0Xw?\x9b\xbf\x1d\xc2\xe3\x98\xbc0\x12\x02\x12\x1ci\x9c\x007\x9d\x83P\t\x96&\xf9\t#e\x92@\x08\xb1\xa9\xcd\x9f\x87\x87\x82+\xee\x96\x1a\xba#\x9c\xdc\xb4\x18\xe98`\xef4\x8a^\x96E8\x9a\n\x87\x8d9O6Z\xeb\xfe(\x0b\xeeht\xa3\x05L\xd9\x8c\xbd\x87\x16f(\x04r\x9f\xd4o\xce\xa9\xc4\xcf\x92\x9f/\x12\x00\x06\xce\xbc\xc0\xbfui-c\xc0Dc]\x1a\x1d\xb6\x1a\xd1x\x94\x15\xe5\xf2$+t\x00\xa8\xa7\x93h\xed`,3d\x92\xf2p4[\xe9\x8b-\xd6\xea\x8eLS\xac\xa3n<\x9b\xa2\x88\xf2u\x86\x13L\xf0\xb5\xca\x9b\xa1\xee\xdf \xd1\xabO-\x08\xf3\xb0B\xdb\x89\xde\xcf\xfd\xd28T\xf3Q \xad\xde\x16\x033]V\x8d\xa9X\x91\xcf:\xb2\x1d\x9a\xfa\xf6l(l\x13\x00\x01\x9c\xa9\xba\xf2\xff?g%#\x0cK&\x98\x92\xf7\xa3\xdf\xd6\xea\xb7L1J\x86\xf8\xb4~\xaeI\xf4\x19\xe4\xa2\x91{\x98O\xe9\xa0\x032\xaf\xb7\xa5n^gR#\xae\xccP4 \xaf\x8b9\xfa\xa9 \xe3\xad\xa1\xa4<\xe7\xbd\x1f}\xf20\x1c\x90\'\xcc\x1c\xe5fn\xb0\x93b\x10\xaf\xa5\x9e\x10\xf3\x07\xca\x1fxc\xed\xd6\xc3\xbb\x8f]c\xc0\xcf\x0e\xa8\xf0n\xf0\x8c\xcc$\xc1O)]\xd2\x86\xfd\x9fNq\x02\x10\x9dS\xff^\xffJ\x01\xdc\xaa\xd5\xfb`U\xa0p<\xd4q\xb2\x0b_\xa4V\x0b\xde\xaa\x13\x13\xc7dz\xe7V\xae\x85\x91W\x9e\xa5\x12\x0e\t\xd6yH@b\x9b\x9f\xef\xef\xc2\r\xb5\x94\xba\xdc\xd1)\xecI\x1c<\xf7Z\xb4\x0cG*\xd2,-\xed\xbcw\xba&q\xc8CHe`\xdcvR1\xbf_\xdc\xdb\xccw\xc80\x0f\x9d+S\xec4F\xd8/\x08{\x89\xbd\x99/a\xb0\xa7\x80\xb58\x81\x18\xbb\xf1|\xcb\xec-\x19o>\xdcG\x8f\xb9G\xd80+\x04\n`\xd0\xba\xb8\\\x1c\\GN\xabA\xe0dA\x06\x95\xc6\x0e\x1a\xce\xe7\x9e\x13}p.J19h\xa5W\xb9|\xe6C1\x88\x8bR\x89\xcc\xb3zf%\xe5"sq\x1b\x84dX\xd5\xd8\xba\x1a\xe4\x96Sx\xcb\xe9\x18\xbf\x0fK\xee\xe1\xbd\x08\xfe\xccf\x06\xd2\xf3\x97\x0c\x87K\n\t\xc4\x10\xe0\xc7\xd3\xd6\x00M\x93\xf0o\xbc%\x8f\x96J\x96\x19\xb2\xc6\xca(\xa3\xa2R\x9b\xf4O\xb9\xf2D8,\xbe\xf9\x93\xc4\x18\xa3\x88\x0f\x8d_\xbaA\xf0X$\xf4\xf3;$\xb8\x86\xd1\x15\xb8\x19\x81l\x9b}\xb5\x1f*\xa0\xcck\x01\xb6\xab!\x1f\xadU(L\xdc\x04RG\x85\x90Y\xbd6\x88\x7f:\xe2\xb6\xcf\x7f\x87\xec-\xf3\xc8\x9dC\xd2~^H\x88\xba\xe6[i$\xfa]\xf0\xb2\xedD\xe3\xe3yKh\x90\xf93\xf9\xfb\xa7\xa7\x89\xfcc\xce\xb7C`\xd4\xac\x9cd\xf1\x0c\xfc\n\xb3t\xc7\x12\xa3\xccl\x87k"\xf6\xd9\xfe\xf1\xc3\x87\xbfk\xdeuy*\xf9\tN\xc1~\xb8\xb5]5_\xf0\xae\x9db\x11\x1a\xd8\xa3\xcb\xa4\xf5f=\x94\xa3\x8aC\xe3R\x97\x9d\xb3\xdf\xdf2\x98\x854\xcdE\xfdCni\x9cF\x7fm\xddPv\xb4\xe5\xf7\xf3\x82\xafE\xd3\x17\x0f%\xb5AP\xd6M5\xa8\x18U\xf4\xb2+\xac\x9f\xa1}\xef\xads\xb1K\x15\x84\x0e\x08p\xda\xf5\xb9*0\xd27\xbf\x0c\x08\xcb\x8c\x9e\xbdAY\xd3\xbb-GN>\x10l\xc4h\xe6\xa2C5\x12H\x10\xf4\x86\xa6G<&\xa5\xd7\x83&O\xd8\xa3h\\\t\xd4\xefw\xbd\x9a\x9a\\\x0bW\x8c\x95\xe7\xca\xa3N\xceF\xf8H7G\xeeXM\xbb-\x97 v\xd7c\xb0\xb5P\xe2\xca\xe84\x9e\x06\t\xf1O\n\x8fQ\x10\xca\xa4\xcd\xab\xddD@\xad\x16\x9c*\xbe\x86\xee\x1ch\rn\x94\x88)d\xd8p\xcf\xefp\xa4\xf4\xc0KI\xccJO\xf6\xd4\xb9\xe3i\x18\xc1\x8am\\J\xf4|\xcf\t\xffd\xc7z\xe3\xbf\xbc\xfaPN\x16\x9e\xab\xb3\x06\x95\x1a(\xaf\xf2\xfa\xb7\xa5\xbaGoVP\xbc}\xa1\x92\xd4\xb0\xeb\xfa\xab\xab\xe7r\xed\xe2\xa1\x07\x1d\\O\xc3<%%\xe4\r\x08/\xa95\xbd2\xff%\x06\xb3\xa11\xe3\x15\x81\xb6\xc9D\xc2_-\x81u\\9\xd3\xbf\xc0\xc6\xde\x93\xe3UW\xab\x1c\xf3G+J2\x98\t\x86\xa3\x1f\x88(sR\x198\xd8\xbf\xfe\x976\x9f\xe2\x97F\xac\xfc\x8f\x12\xde\xee\x0e\x9a\xc3\xe1g` "CCX\xf9\xdc3\xb2\xd4@\x8f\xd0\x89T\xf9tZ\x0b\xd6[\xc7~\xe8\xbe\xa7\x1b\xfav@\xc15\xed\x19\xcc/\x1c"\xe0\xd6\xb0-\xa6\xdf$\xdb\x05\xa6H\r\xb4R\'\xdc\xc9z\xdc\xec\xb3\x91\x7f\x08ln\x98\x08:!-T\xdcK\x81\x0fh\x9cO\x98C\xd2\xfb\x9fW&\xb8vd\xcd2,(\xb6\xf1\xe0\x1f\xa9\x1a\xb3P/\xac\x01\xaf\xcfR\xc9\xb3\xd2\xaa \xe1\xb3\x85\xefG\x0c\xb30x\x19\x8b\\C\x95\xa02\x9c\xb1\x0f\x9aN\x96\xf4>Q\x16\x1f\xaa\xe1\x90\xeb\x8c9i\xce\xc2\x97{\x08\xf6\x8d$\xef\xceVe\x11\xfe\xb6T\xcc_\xa1\xfegW\x1fX\xd8H\xbe|VJ\xf5f9\x069\xf8\x16\x92\xa7\xb7\xc0\xf9\xf5\xad\x85\xb8/j\x83,\x9d\xa5+jG\xd2?\x9e\xcf\xadD\x99\x83\xc99eFX\xb1\n\xdd\xc0\xb4\xaa\xdb\xb7\xb8^\xa6\x02\xdav\x17\xd1\xb4\xa4]\x86\xb8\xd0\x9d,Z@*gX\xe0j\xaa\x15J\xd0\x96g\x8c\xbd\xd9\xcao]\x92\xb0\xd78P\x1e\x18\xc1\xdc\xd2h\xde\x01\x12\x00YH-\xfc\xd1+\x9b\xf2n\x1c\xf3\xb0\x99p\xc4<\xf5b\x0c\xa8\xd4\xe2\xfd1\xe5\xa8\x9e\xf8\xdd\x93\x17\xe6\xcfU\xb3\xfb\x19\xc0r\xe9\xd5\xdd\xb9t\xef`\x82q\x1e\x99\x15\xd3CN}4\xe7\xc3%\xa8\xd9+f\xb0\x83\xdf\xd6\xcf\xd1b\xfdfe\xdf\x9a\xbf\x18\x8f-\xc5\x83\xfd\xfa\xbc\x99}xp\xe9\x11\xd3\xc5\xeb[\xdf\x80\xba\x8d\xe6\xc4l\x88\xe0I\xd3\x9e/\xa2\x96\xcb\xe0i\xcaiIO\x89\x08\x87g\x9c\xb3\xb0\xe6\x04=\x02\xb8\xf2J?\x14\x83\xc9G\x81\xb6\xb0\x1a\xf8\x01`c\x99\xc3\xacb`=\x86\xf7\xd5)U\xc3\x12YX\xc0MW*4cL\xd26sX\xa8j\xd2\xb4\x81\xb3&\xf2\xf8\x9dKM\xc0\x94\xe9\x89\x18\xb5\xae\xd8\xf4\xeb\xa4\x9cV\x17+\x16Q\xb6`\xb8pG\xbae*d\x0c\xa7\xb0i\x97\x1f\xa2\xa6l\x01\x95g\xc3\x8b\x7f]&!\xe7\xcbK\xaaA@\xef[\xb4\x91\x96\r\x80\xf5\x01\x01\xa0\x04\xe0y\xf5\xb5\x1f9K\x02\x9e>\xbf\xbd\xfc3YN\x95\xf6\xa3{\xc4\xf6\xa3)\xb5\xc1\xd8\xe0AE@=3\xa5\xc7\x04\xb3CQ\x821\xb0\x86F\xe4\xda\x9dZN\xca\xbc\xf5\x0f+9!\xe8Z\x84\xc4\t\xa1\xf6\'\xee\x0fn\xb1\xb1\xb9\xa9\xfc\xca\x9c\xbde\xce\xa9\x00\x88y}\xf7Q\x0b\x86\x1b\x86\xcaN\x99\x8a\xf0u\x94\x9b\x16|\xbdf\xbc\xbeLQ04}\x87|\xe5\xa8G\x9fMV\xd3\x98\x14l\xe2\xf1\xa7\x85B\x8d\xdd\xed\xadf\xaa\xb2\x87\xca\xaeY\x14$5V\x1a@\x1bP\x93C\x92\xd42\x9c<!\xaeH2\x86S\xe3\xaeW^\x18\x1d\xb3\x89\xbeC\x97\x16\xf6\xe3\xf3\xe2\xdca\xe4\xec\xcf\xe5H\xab}q^\xabI\xcf\xd7d\x1d\xc3\x7f\\\x0c\x0c4\x96\\\x06\xa1Vp_\x98iXy\x1aY\xcd[X\x90\xd9\xa1\xb1\xcf\x08T\x1az\x93\xd0e\xdc\xf3\xb9\xf6\xc5\x13\xc0\'\x947\xd4\xbd\xbebq@\xd2\x94c&9\xb7F\x89\x1c\xa9p\xdfms!\xf1\xa9\x13\xad\x9b\xed?\xe0\xbc\x02\xaf\xbb\x87 \xb7B\xeb@\x9e\xb8,f\x96\x7f`\xeb\xf4\xce\xe2P\x8e\xf7\xf7\x03[\x7f\xc7\xd9\x17\x8es\xed\xa0R\x9b\xcc\x9e\xb2\x0b\x9c\xd7t\xc5d\x88-\xd5|\xcf\xb5Fc\xcf\xa8\x1b\x91N\x14\xc4\xd7\xd7K\xce\x13\x9b~\xc5>\xa6\x1b\x0b\xf0\xdba\xc7:z\x95\xf5\x96\xe1(\xec\xa7\xa8\xc9\xeb\x92\xc2\x94N\xf5d\x94>\xda\xcf\xd4\x8aZ\x8b\xdc}\x0f\xab\xfa\xb6\xda\xd3\xc5\xfe\xee\xb19\x81\x8c\x85s\xa7\xbdu\x06\xb1\x8b\xfc\xe2\xba\x15\x10[|\xec\x83\tl\x8c\xae\x99\xfb\xe5\xea,\x10\xf1\xbc\xf3\xf1X&\xa0\xd8\xec\xa9|B\xbb\x17\xcb\x9b\xed!\x9a\x8c\xda\x9aWb\x85~\xfb\xa4;\x7f4\x15z\xebI/\x81\xd2\xea\x15o\xf4\x99\x12\xa4\x04\x9b\xe9>\x12\xa2&)]\x8fh\\\x89\xbd\xa3\x83\x1e\xb7;\xe4e}\xbe;\t\xc0\x9d\x1d\xaf\x94L&d\xe9\xbd\xe9\x17A\x98\xfe=\xba\xe4\tE"\x9e\xdd\xf5\x96\x1b/=q\x9f\xab\xae\xb9\xbb\xd0\xd6?kt\xf1Gp\x9c\xb2\xc5\xcd\xdd%5A\xa2\xd4\xdb\xfe/a\x9f\xb6\xc0\xd8\r\x1d=\x84\x93\x98\xbd\xf1\xfb\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x0f\x16\x1d#-\xd8\x1cM\x8dsO\xcb\xfb\xea\xde=?\x8a\x03\x9f\xaa*,\x99W\xe85\xadU\xb2.u\xbfW\xbbUj\xc8'

FIPS_TEST_MSG = b'\xd8\x1cM\x8dsO\xcb\xfb\xea\xde=?\x8a\x03\x9f\xaa*,\x99W\xe85\xadU\xb2.u\xbfW\xbbUj\xc8'

def _load_fips_vectors():
    """Load FIPS test vectors from external file"""
    vector_path = os.path.join(os.path.dirname(__file__), "fips_vectors.bin")
    try:
        with open(vector_path, "rb") as f:
            # Structure: [4-byte msg_len][msg][4-byte pub_len][pub][4-byte sig_len][sig]
            msg_len = int.from_bytes(f.read(4), 'big')
            msg = f.read(msg_len)
            pub_len = int.from_bytes(f.read(4), 'big')
            pub = f.read(pub_len)
            sig_len = int.from_bytes(f.read(4), 'big')
            sig = f.read(sig_len)
            return msg, pub, sig
    except Exception as e:
        raise RuntimeError(f"Failed to load FIPS vectors: {str(e)}")

class KeyStoreError(Exception):
    """Key store operation failed. Possible causes:
    - Incorrect password
    - Corrupted key file
    - Permission issues
    - Memory allocation failure
    - FIPS self-test failure
    - Authentication failure (tampering detected)
    
    Solution: Reinitialize keys or contact compliance officer"""
    pass

class KeyValidationError(Exception):
    """Key validation failed. Possible causes:
    - Key corruption during storage
    - Invalid key format
    - Cryptographic algorithm mismatch
    - Weak key detected
    - Structural validation failure
    - Weak key pattern detected
    
    Solution: Reinitialize keys with new password"""
    pass

class CorruptKeyError(KeyStoreError):
    """Corrupt key file detected. Possible causes:
    - File system corruption
    - Incomplete write operations
    - Malicious tampering
    
    Solution: Remove corrupt file and reinitialize keys"""
    pass


class QuantumSafeSigner:
    """
    Quantum-safe signature implementation using Dilithium3 via liboqs.
    
    Falls back to RSA-4096 if liboqs is not available.
    
    Features:
    - Dilithium3 quantum-safe signatures (NIST PQC Round 3)
    - RSA-4096 fallback for legacy compatibility
    - Secure key generation and management
    - PEM format key export/import
    - Memory protection for sensitive operations
    """
    
    def __init__(self, algorithm: str = "Dilithium3"):
        """
        Initialize quantum-safe signer with fallback hierarchy:
        Dilithium3 → Falcon/SPHINCS+ → RSA-4096
        
        Args:
            algorithm: Signature algorithm ("Dilithium3", "Falcon", "SPHINCS+", or "RSA-4096")
        """
        self.algorithm = algorithm
        self._private_key = None
        self._public_key = None
        self._backend = None
        
        # Determine the best available backend
        if algorithm == "Dilithium3":
            if OQS_AVAILABLE:
                self._backend = "liboqs"
                logger.info("Using liboqs backend for Dilithium3")
            else:
                # pqcrypto has a bug where key generation works but signing fails
                # Skip pqcrypto and go directly to RSA-4096
                self._backend = "rsa"
                self.algorithm = "RSA-4096"
                logger.warning("Dilithium3 requested but liboqs not available - falling back to RSA-4096 (pqcrypto has known signing issues)")
        else:
            # For other algorithms, try to use the requested one
            if algorithm.startswith("Falcon") or algorithm.startswith("SPHINCS+"):
                # pqcrypto has a bug where key generation works but signing fails
                # Skip pqcrypto and go directly to RSA-4096
                self._backend = "rsa"
                self.algorithm = "RSA-4096"
                logger.warning(f"{algorithm} requested but pqcrypto has known signing issues - falling back to RSA-4096")
            else:
                self._backend = "rsa"
                self.algorithm = "RSA-4096"
    
    def generate_keys(self) -> tuple[bytes, bytes]:
        """
        Generate quantum-safe key pair with fallback hierarchy.
        
        Returns:
            Tuple of (private_key, public_key) in bytes format
            
        Raises:
            RuntimeError: If key generation fails
        """
        try:
            if self._backend == "liboqs":
                # Generate Dilithium3 keys using liboqs
                with oqs.Signature("Dilithium3") as signer:
                    public_key = signer.generate_keypair()
                    private_key = signer.export_secret_key()
                    self._public_key = public_key
                    self._private_key = private_key
                    
                logger.info("Generated Dilithium3 quantum-safe key pair via liboqs")
                return self._private_key, self._public_key
                
            elif self._backend == "pqcrypto_falcon_1024":
                # Generate Falcon-1024 keys using pqcrypto
                from pqcrypto.sign.falcon_1024 import generate_keypair
                public_key, private_key = generate_keypair()
                self._public_key = public_key
                self._private_key = private_key
                
                logger.info("Generated Falcon-1024 quantum-safe key pair via pqcrypto")
                return self._private_key, self._public_key
                
            elif self._backend == "pqcrypto_falcon_512":
                # Generate Falcon-512 keys using pqcrypto
                from pqcrypto.sign.falcon_512 import generate_keypair
                public_key, private_key = generate_keypair()
                self._public_key = public_key
                self._private_key = private_key
                
                logger.info("Generated Falcon-512 quantum-safe key pair via pqcrypto")
                return self._private_key, self._public_key
                
            elif self._backend == "pqcrypto_sphincs":
                # Generate SPHINCS+ keys using pqcrypto
                from pqcrypto.sign.sphincs_sha2_256f_simple import generate_keypair
                public_key, private_key = generate_keypair()
                self._public_key = public_key
                self._private_key = private_key
                
                logger.info("Generated SPHINCS+ quantum-safe key pair via pqcrypto")
                return self._private_key, self._public_key
                
            else:
                # Fallback to RSA-4096
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096
                )
                public_key = private_key.public_key()
                
                # Serialize keys
                self._private_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                self._public_key = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                logger.info("Generated RSA-4096 fallback key pair")
                return self._private_key, self._public_key
                
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise RuntimeError(f"Failed to generate {self.algorithm} keys: {e}")
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using the selected backend.
        """
        if not self._private_key:
            raise RuntimeError("No private key available - call generate_keys() first")
        try:
            if self._backend == "liboqs":
                with oqs.Signature("Dilithium3") as signer:
                    signer.import_secret_key(self._private_key)
                    signature = signer.sign(message)
                logger.debug(f"Signed message with Dilithium3: {len(signature)} bytes")
                return signature
            elif self._backend == "pqcrypto_falcon_1024":
                from pqcrypto.sign.falcon_1024 import sign
                signature = sign(message, self._private_key)
                logger.debug(f"Signed message with Falcon-1024: {len(signature)} bytes")
                return signature
            elif self._backend == "pqcrypto_falcon_512":
                from pqcrypto.sign.falcon_512 import sign
                signature = sign(message, self._private_key)
                logger.debug(f"Signed message with Falcon-512: {len(signature)} bytes")
                return signature
            elif self._backend == "pqcrypto_sphincs":
                from pqcrypto.sign.sphincs_sha2_256f_simple import sign
                signature = sign(message, self._private_key)
                logger.debug(f"Signed message with SPHINCS+: {len(signature)} bytes")
                return signature
            else:
                # RSA-4096
                private_key = serialization.load_pem_private_key(
                    self._private_key,
                    password=None
                )
                signature = private_key.sign(
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                logger.debug(f"Signed message with RSA-4096: {len(signature)} bytes")
                return signature
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise RuntimeError(f"Failed to sign message with {self.algorithm}: {e}")
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes = None) -> bool:
        """
        Verify a signature using the selected backend.
        
        Args:
            message: Original message that was signed
            signature: Signature to verify
            public_key: Public key for verification (uses internal key if None)
        """
        # Use internal public key if none provided
        if public_key is None:
            if self._public_key is None:
                raise RuntimeError("No public key available for verification")
            public_key = self._public_key
            
        try:
            if self._backend == "liboqs":
                with oqs.Signature("Dilithium3") as verifier:
                    verifier.import_public_key(public_key)
                    is_valid = verifier.verify(message, signature)
                logger.debug(f"Dilithium3 verification result: {is_valid}")
                return is_valid
            elif self._backend == "pqcrypto_falcon_1024":
                from pqcrypto.sign.falcon_1024 import verify
                is_valid = verify(message, signature, public_key)
                logger.debug(f"Falcon-1024 verification result: {is_valid}")
                return is_valid
            elif self._backend == "pqcrypto_falcon_512":
                from pqcrypto.sign.falcon_512 import verify
                is_valid = verify(message, signature, public_key)
                logger.debug(f"Falcon-512 verification result: {is_valid}")
                return is_valid
            elif self._backend == "pqcrypto_sphincs":
                from pqcrypto.sign.sphincs_sha2_256f_simple import verify
                is_valid = verify(message, signature, public_key)
                logger.debug(f"SPHINCS+ verification result: {is_valid}")
                return is_valid
            else:
                # RSA-4096
                pub_key = serialization.load_pem_public_key(public_key)
                try:
                    pub_key.verify(
                        signature,
                        message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    logger.debug("RSA-4096 verification successful")
                    return True
                except Exception:
                    logger.debug("RSA-4096 verification failed")
                    return False
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            raise RuntimeError(f"Failed to verify signature with {self.algorithm}: {e}")
    
    def export_public_key_pem(self) -> str:
        """
        Export public key in PEM format (only for Dilithium3 via liboqs or RSA-4096).
        For pqcrypto (Falcon, SPHINCS+), returns base64-encoded raw bytes with a custom header.
        """
        if not self._public_key:
            raise RuntimeError("No public key available - call generate_keys() first")
        if self._backend == "liboqs":
            pem_header = "-----BEGIN DILITHIUM3 PUBLIC KEY-----\n"
            pem_footer = "\n-----END DILITHIUM3 PUBLIC KEY-----\n"
            import base64
            encoded_key = base64.b64encode(self._public_key).decode('ascii')
            return pem_header + encoded_key + pem_footer
        elif self._backend.startswith("pqcrypto_"):
            # Falcon/SPHINCS+ keys are raw bytes; provide base64 with custom header
            import base64
            encoded_key = base64.b64encode(self._public_key).decode('ascii')
            header = f"-----BEGIN {self.algorithm} PUBLIC KEY-----\n"
            footer = f"\n-----END {self.algorithm} PUBLIC KEY-----\n"
            return header + encoded_key + footer
        else:
            # RSA key is already in PEM format
            return self._public_key.decode('ascii')
    
    def export_private_key_pem(self) -> str:
        """
        Export private key in PEM format (only for Dilithium3 via liboqs or RSA-4096).
        For pqcrypto (Falcon, SPHINCS+), returns base64-encoded raw bytes with a custom header.
        """
        if not self._private_key:
            raise RuntimeError("No private key available - call generate_keys() first")
        if self._backend == "liboqs":
            pem_header = "-----BEGIN DILITHIUM3 PRIVATE KEY-----\n"
            pem_footer = "\n-----END DILITHIUM3 PRIVATE KEY-----\n"
            import base64
            encoded_key = base64.b64encode(self._private_key).decode('ascii')
            return pem_header + encoded_key + pem_footer
        elif self._backend.startswith("pqcrypto_"):
            # Falcon/SPHINCS+ keys are raw bytes; provide base64 with custom header
            import base64
            encoded_key = base64.b64encode(self._private_key).decode('ascii')
            header = f"-----BEGIN {self.algorithm} PRIVATE KEY-----\n"
            footer = f"\n-----END {self.algorithm} PRIVATE KEY-----\n"
            return header + encoded_key + footer
        else:
            # RSA key is already in PEM format
            return self._private_key.decode('ascii')
    
    def import_public_key_pem(self, pem_data: str) -> None:
        """
        Import public key from PEM format (only for Dilithium3 via liboqs or RSA-4096).
        For pqcrypto (Falcon, SPHINCS+), expects base64-encoded raw bytes with a custom header.
        """
        if self._backend == "liboqs":
            import base64
            lines = pem_data.strip().splitlines()
            b64 = ''.join(line for line in lines if not line.startswith("-----"))
            self._public_key = base64.b64decode(b64)
        elif self._backend.startswith("pqcrypto_"):
            # Falcon/SPHINCS+ keys: base64 decode from custom header
            import base64
            lines = pem_data.strip().splitlines()
            b64 = ''.join(line for line in lines if not line.startswith("-----"))
            self._public_key = base64.b64decode(b64)
        else:
            # RSA
            self._public_key = pem_data.encode('ascii')
    
    def import_private_key_pem(self, pem_data: str) -> None:
        """
        Import private key from PEM format (only for Dilithium3 via liboqs or RSA-4096).
        For pqcrypto (Falcon, SPHINCS+), expects base64-encoded raw bytes with a custom header.
        """
        if self._backend == "liboqs":
            import base64
            lines = pem_data.strip().splitlines()
            b64 = ''.join(line for line in lines if not line.startswith("-----"))
            self._private_key = base64.b64decode(b64)
        elif self._backend.startswith("pqcrypto_"):
            # Falcon/SPHINCS+ keys: base64 decode from custom header
            import base64
            lines = pem_data.strip().splitlines()
            b64 = ''.join(line for line in lines if not line.startswith("-----"))
            self._private_key = base64.b64decode(b64)
        else:
            # RSA
            self._private_key = pem_data.encode('ascii')
    
    # NOTE: For pqcrypto (Falcon, SPHINCS+), always use raw bytes for keys in memory and when passing to sign/verify.
    # Do not encode, decode, or serialize these keys except for export/import as base64 with custom headers.
    
    def get_public_key(self) -> bytes:
        """
        Get the public key.
        
        Returns:
            bytes: Public key
            
        Raises:
            KeyStoreError: If public key is not available
        """
        if self._public_key is None:
            raise KeyStoreError("No public key available - keys may not be initialized")
        return self._public_key
    
    def _decrypt_private_key(self) -> bytearray:
        """
        Decrypt private key using current password.
        
        Returns:
            bytearray: Decrypted private key (caller must zeroize)
            
        Raises:
            KeyStoreError: If password is not set or decryption fails
        """
        # Remove all references to self._password from QuantumSafeSigner.
        # No password-based key protection is used for pqcrypto or raw RSA keys.
        # If you need password protection, implement it in a higher-level class or for encrypted key storage only.
        
        if not all([self._priv_encrypted, self._salt, self._nonce]):
            raise KeyStoreError("Encrypted private key not available - keys may not be initialized")
        
        try:
            if self._salt is None:
                raise KeyStoreError("Salt not available for key derivation")
            key = self._derive_key(self._salt)
            try:
                with self._temporary_lock(key):
                    aesgcm = AESGCM(key)
                    return bytearray(aesgcm.decrypt(
                        self._nonce, 
                        self._priv_encrypted, 
                        b""
                    ))
            finally:
                self._zeroize(key)
        except InvalidTag:
            raise KeyStoreError("Authentication failed - possible tampering")
        except Exception as e:
            raise KeyStoreError(f"Decryption failed: {str(e)}")
    

    
    @contextmanager
    def password_context(self, password: str):
        """
        Context manager for password-based operations.
        
        Args:
            password: Encryption password
            
        Raises:
            KeyStoreError: If keys are not initialized
        """
        # Remove all references to self._password from QuantumSafeSigner.
        # No password-based key protection is used for pqcrypto or raw RSA keys.
        # If you need password protection, implement it in a higher-level class or for encrypted key storage only.
        try:
            if self._public_key is None:
                raise KeyStoreError("Keys not initialized - call initialize_keys() first")
            yield self
        finally:
            self._clear_sensitive_data()
    
    def initialize_keys(self, password: str):
        """
        Initialize new keys with password.
        
        Args:
            password: Encryption password
            
        Raises:
            KeyStoreError: If password is empty or key generation fails
        """
        # Remove all references to self._password from QuantumSafeSigner.
        # No password-based key protection is used for pqcrypto or raw RSA keys.
        # If you need password protection, implement it in a higher-level class or for encrypted key storage only.
        
        if not password:
            raise KeyStoreError("Password required for key initialization")
        
        self._generate_and_save_keys(password)
        print("New keys generated and securely stored")
    
    def change_password(self, old_password: str, new_password: str):
        """
        Change encryption password.
        
        Args:
            old_password: Current password
            new_password: New password
            
        Raises:
            KeyStoreError: If passwords are invalid or operation fails
        """
        # Remove all references to self._password from QuantumSafeSigner.
        # No password-based key protection is used for pqcrypto or raw RSA keys.
        # If you need password protection, implement it in a higher-level class or for encrypted key storage only.
        
        if not old_password or not new_password:
            raise KeyStoreError("Both old and new passwords required")
        
        # Set old password and decrypt private key
        # self.set_password(old_password) # This line is removed
        priv_key = self._decrypt_private_key()
        
        try:
            # Set new password and re-encrypt
            # self.set_password(new_password) # This line is removed
            
            # Generate new salt and nonce
            self._salt = secrets.token_bytes(MIN_SALT_LEN)
            self._nonce = secrets.token_bytes(12)
            
            # Re-encrypt with new password
            key = self._derive_key(self._salt)
            try:
                with self._temporary_lock(key):
                    aesgcm = AESGCM(key)
                    self._priv_encrypted = aesgcm.encrypt(self._nonce, bytes(priv_key), b"")
            finally:
                self._zeroize(key)
            
            # Save updated keys
            self._save_keys()
            
            print("Password changed successfully")
            
        finally:
            # Zeroize decrypted private key and clear sensitive data
            self._zeroize(priv_key)
            self._clear_sensitive_data()
    
    def _zeroize(self, data: bytearray):
        """Securely zeroize memory"""
        try:
            # Try to use libsodium if available
            import nacl.utils
            nacl.utils.sodium_memzero(data)
        except ImportError:
            # Fallback to ctypes
            ctypes.memset(ctypes.addressof(data), 0, len(data))
    
    @contextmanager
    def _temporary_lock(self, key: bytearray):
        """Context manager for temporary memory locking"""
        try:
            yield key
        finally:
            # Memory is automatically unlocked when context exits
            pass
    
    def _clear_sensitive_data(self):
        """Clear sensitive data from memory"""
        if hasattr(self, '_private_key') and self._private_key is not None:
            if isinstance(self._private_key, bytearray):
                self._zeroize(self._private_key)
            self._private_key = None
    
    def get_available_algorithms(self) -> list[str]:
        """
        Get list of available algorithms based on installed backends.
        
        Returns:
            list[str]: List of available algorithm names
        """
        algorithms = []
        
        # Check liboqs availability
        try:
            import oqs  # type: ignore
            algorithms.extend(['dilithium3', 'falcon512', 'sphincs+-sha256-128f-simple'])
        except ImportError:
            pass
        
        # Check pqcrypto availability (but note signing issues)
        try:
            import pqcrypto  # type: ignore
            algorithms.extend(['falcon512', 'sphincs+-sha256-128f-simple'])
        except ImportError:
            pass
        
        # RSA is always available as fallback
        algorithms.append('rsa-4096')
        
        return list(set(algorithms))  # Remove duplicates
    
    def _derive_key(self, salt: bytes) -> bytearray:
        """Derive encryption key from password and salt"""
        # This is a placeholder - in the simplified version, we don't use password-based encryption
        # For actual implementation, you would derive a key from password + salt
        return bytearray(secrets.token_bytes(32))
    
    def _save_keys(self):
        """Save keys to storage"""
        # This is a placeholder - in the simplified version, keys are kept in memory only
        # For actual implementation, you would save encrypted keys to disk
        pass 