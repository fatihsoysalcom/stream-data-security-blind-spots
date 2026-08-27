# Stream Data Security Blind Spots

This example demonstrates why traditional security scanners struggle with real-time stream data, leading to 'blind spots'. It simulates a stream of financial transactions, including a rapid sequence of small, suspicious transactions. A 'traditional' batch scanner attempts to find threats by analyzing all data after it's collected, often missing temporal patterns. In contrast, a 'stream-based' scanner processes data as it arrives, maintaining a time-based window to detect dynamic threats like rapid transaction sequences.

## Language

`python`

## How to Run

Save the code as `main.py`.
Run from your terminal: `python main.py`

## Original Article

This example accompanies the Turkish article: [Güvenlik Tarayıcıları Akış Verilerindeki Tehditleri Neden Göremiyor?](https://fatihsoysal.com/blog/guvenlik-tarayicilari-akis-verilerindeki-tehditleri-neden-goremiyor/).

## License

MIT — see [LICENSE](LICENSE).
