# file điều hướng mọi lệnh, chỉ chạy các lệnh ở trong này
# entry point duy nhất

import sys

from idscore.cli import main


if __name__ == "__main__":
    sys.exit(main())
