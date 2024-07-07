from packet import CaseTCP 

MAX_LEN = 1400
MSS = MAX_LEN - len(CaseTCP())

# window variables
WINDOW_SIZE = MSS * 32
WINDOW_INITIAL_WINDOW_SIZE = MSS
WINDOW_INITIAL_SSTHRESH = MSS * 64

# timeout in seconds
DEFAULT_TIMEOUT = 3

# max TCP buffer
MAX_NETWORK_BUFFER = 65535
