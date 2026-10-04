/**
 * 用 fetch 读 SSE 流。
 *
 * 为什么不用 EventSource：它没法带 `AbortController` 之外的取消手段，
 * 而这个页面要能随时断开一条跑了半小时的进度流。fetch + ReadableStream 两全。
 *
 * @returns {AbortController} 调 .abort() 可随时断开
 */
export function openProgressStream(scanId, { onData, onDone, onError } = {}) {
  const controller = new AbortController()

  ;(async () => {
    try {
      const response = await fetch(`/api/scans/${scanId}/progress`, {
        signal: controller.signal,
      })
      if (!response.ok || !response.body) {
        throw new Error(`HTTP ${response.status}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        // SSE 以空行分帧
        const frames = buffer.split('\n\n')
        buffer = frames.pop() ?? ''
        for (const frame of frames) {
          const line = frame.split('\n').find((l) => l.startsWith('data:'))
          if (!line) continue
          let payload
          try {
            payload = JSON.parse(line.slice(5).trim())
          } catch {
            continue
          }
          onData?.(payload)
          if (!['running', 'finalizing'].includes(payload.status)) {
            controller.abort() // 服务端此刻也会关流，这里主动收尾
            onDone?.(payload)
            return
          }
        }
      }
      onDone?.()
    } catch (error) {
      if (error.name === 'AbortError') return // 主动断开，不算错误
      onError?.(error)
    }
  })()

  return controller
}
