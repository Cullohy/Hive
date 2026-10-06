/**
 * 时间格式化 —— 一律按**中国时区（UTC+8）**输出。
 *
 * ## 为什么要专门写一个
 *
 * 库里存的是 UTC ISO 串（`2026-10-06T13:05:52+00:00`）。之前三个页面都是
 * ``String(iso).slice(5, 16).replace('T', ' ')`` 这么直接切字符串 ——
 * 切出来的是 **UTC 墙钟**，却被当成北京时间显示，整个界面**慢 8 小时**。
 *
 * ## 为什么不用 dayjs 的 timezone 插件
 *
 * dayjs 的 `timezone` 依赖 IANA 时区数据（要额外装 `dayjs/plugin/utc`），
 * 而中国是**固定 UTC+8、不实行夏令时**，没有"历史规则"可言。加 8 小时
 * 得到的永远是正确结果，为此引入一个插件不划算。
 *
 * ## 为什么要用 getUTC* 取值
 *
 * 加完 8 小时之后**必须用 UTC 取件器**读月/日/时/分。
 * 用 getDate()/getHours() 读的是"观看者自己机器"的时区 —— 那就让结果
 * 取决于看的人在哪台机器上，恰恰是原来那个 bug 的翻版。
 */

const CN_OFFSET_MIN = 8 * 60

/** 解析 ISO 串；解析不了就返回 null（不抛，界面不能为一个坏时间崩掉）。 */
function parse(iso) {
  if (!iso) return null
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}

const pad = (n) => String(n).padStart(2, '0')

/**
 * ISO → `2026-10-06 21:05`（北京时区，带年）。
 * 解析不了时退回原始串的前 19 位，至少还能看出点东西。
 */
export function cnDateTime(iso) {
  const d = parse(iso)
  if (!d) return iso ? String(iso).slice(0, 19).replace('T', ' ') : '—'
  const t = new Date(d.getTime() + CN_OFFSET_MIN * 60_000)
  return (
    `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())}`
    + ` ${pad(t.getUTCHours())}:${pad(t.getUTCMinutes())}`
  )
}

/**
 * 曾有一个不带年的 ``cnShort``，用了一阵就删了 —— 三个页面全是**跨扫描**的
 * 列表，12 月和 1 月的记录会挨在一起，不带年份分不出跨年，看着像同一天。
 * 与其让每个调用点自己记得传 ``withYear``，不如只留一个带年的。
 */

/** ISO → `2026-10-06`（北京时区，只要日期）。 */
export function cnDate(iso) {
  const d = parse(iso)
  if (!d) return iso ? String(iso).slice(0, 10) : '—'
  const t = new Date(d.getTime() + CN_OFFSET_MIN * 60_000)
  return `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())}`
}
