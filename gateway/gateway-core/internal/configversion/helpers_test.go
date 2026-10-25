package configversion

import (
	"strconv"
	"time"
)

// timeZero 返回固定时间戳（避免单测依赖墙钟）。
func timeZero() time.Time {
	return time.Unix(1725500000, 0).UTC()
}

// itoa 整数转字符串（测试辅助）。
func itoa(v int) string {
	return strconv.Itoa(v)
}
