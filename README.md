# PcapParser

[![CI](https://github.com/krisarmstrong/pcap-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/krisarmstrong/pcap-parser/actions)
[![Coverage](https://img.shields.io/badge/coverage-80%25-green)](https://github.com/krisarmstrong/pcap-parser)
[![PyPI](https://img.shields.io/pypi/v/pcap-parser.svg)](https://pypi.org/project/pcap-parser/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/krisarmstrong/pcap-parser/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)

Parses PCAP files, filters packets by source MAC (00:c0:17) and port 3842, and outputs details.

## Installation

```bash
git clone https://github.com/krisarmstrong/pcap-parser
cd pcap-parser
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python pcap_parser.py input.pcap output.txt --verbose
```

- `input_file`: Input PCAP file.
- `output_file`: Output text file for packet details.
- `-v, --verbose`: Enable verbose logging.
- `--logfile`: Log file path (default: pcap_parser.log).

## Files

- `pcap_parser.py`: Main script.
- `version_bumper.py`: Version management tool.
- `tests/test_pcap_parser.py`: Pytest suite.
- `requirements.txt`: Dependencies.
- `CHANGELOG.md`: Version history.
- `LICENSE`: MIT License.
- `CONTRIBUTING.md`: Contribution guidelines.
- `CODE_OF_CONDUCT.md`: Contributor Covenant.

## GitHub Setup

```bash
gh repo create pcap-parser --public --source=. --remote=origin
git init
git add .
git commit -m "Initial commit: PcapParser v1.0.1"
git tag v1.0.1
git push origin main --tags
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License. See [LICENSE](LICENSE) for details.