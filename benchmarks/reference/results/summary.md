| Cell | Target | Value | Other | Noisy/failed/errors |
|---|---|---|---|---|
| associations:1 | libiec61850 | 18,065 (IQR 16,673-19,647, range 7,311-20,542) reads/s | p50 45.4 (IQR 44.0-48.2, range 42.6-58.3) us; p99 127 us; server 13.4 us CPU/read (0.23 core); client 1.03 core; connect 0.47 ms; up 1 | 2/0/0 |
| associations:1 | openiec61850 | 13,248 (IQR 12,190-13,551, range 5,002-14,596) reads/s | p50 65.6 (IQR 63.8-70.7, range 58.0-74.5) us; p99 165 us; server 34.2 us CPU/read (0.45 core); client 0.84 core; connect 0.49 ms; up 1 | 2/0/0 |
| associations:16 | openiec61850 | 109,049 (IQR 105,007-109,938, range 79,369-110,425) reads/s | p50 139.0 (IQR 138.0-142.6, range 137.6-167.6) us; p99 291 us; server 9.1 us CPU/read (0.99 core); client 1.75 core; connect 0.22 ms; up 16 | 3/0/0 |
| associations:2 | libiec61850 | 38,742 (IQR 23,730-39,047, range 14,848-40,082) reads/s | p50 48.7 (IQR 48.0-54.6, range 37.6-59.3) us; p99 117 us; server 11.0 us CPU/read (0.42 core); client 1.28 core; connect 20.53 ms; up 2 | 2/0/0 |
| associations:2 | openiec61850 | 29,343 (IQR 26,215-30,448, range 10,233-31,082) reads/s | p50 62.7 (IQR 61.2-65.9, range 43.3-73.3) us; p99 126 us; server 21.8 us CPU/read (0.64 core); client 1.03 core; connect 0.52 ms; up 2 | 1/0/0 |
| associations:256 | openiec61850 | 80,808 (IQR 74,348-84,247, range 66,093-87,361) reads/s | p50 2,845.0 (IQR 2,719.4-3,181.1, range 2,612.3-3,686.1) us; p99 5722 us; server 12.4 us CPU/read (1.00 core); client 1.59 core; connect 0.22 ms; up 256 | 2/0/0 |
| associations:4 | libiec61850 | 37,225 (IQR 19,845-37,959, range 15,645-39,240) reads/s | p50 51.3 (IQR 49.0-59.6, range 39.4-119.1) us; p99 113 us; server 11.7 us CPU/read (0.42 core); client 1.27 core; connect 20.50 ms; up 2 | 3/0/0 |
| associations:4 | openiec61850 | 76,827 (IQR 74,052-80,468, range 11,856-82,073) reads/s | p50 47.7 (IQR 47.3-49.2, range 47.1-106.5) us; p99 130 us; server 12.2 us CPU/read (0.94 core); client 1.58 core; connect 0.35 ms; up 4 | 3/0/0 |
| associations:64 | openiec61850 | 107,998 (IQR 105,070-110,811, range 99,050-113,584) reads/s | p50 563.5 (IQR 554.3-570.7, range 548.6-597.0) us; p99 1022 us; server 9.3 us CPU/read (1.00 core); client 1.70 core; connect 0.22 ms; up 64 | 1/0/0 |
| client/client_example2_discovery | libiec61850 | 64.97 (IQR 64.91-65.13, range 64.86-65.47) ms | | 3/0/0 |
| client/client_example2_discovery | openiec61850 | 64.91 (IQR 64.88-65.13, range 64.87-65.33) ms | | 2/0/0 |
| client/client_example4_dataset | libiec61850 | 33.04 (IQR 32.82-33.17, range 32.72-65.40) ms | | 2/0/0 |
| client/client_example4_dataset | openiec61850 | 32.84 (IQR 32.74-33.43, range 32.66-65.38) ms | | 1/0/0 |
| client/mms_utility_identify | libiec61850 | 32.79 (IQR 32.78-32.95, range 32.78-33.33) ms | | 4/0/0 |
| client/mms_utility_identify | openiec61850 | 32.84 (IQR 32.78-32.98, range 32.65-33.33) ms | | 3/0/0 |
| client/mms_utility_read | libiec61850 | 32.77 (IQR 32.76-33.05, range 32.70-33.29) ms | | 2/0/0 |
| client/mms_utility_read | openiec61850 | 32.82 (IQR 32.77-32.92, range 32.72-33.23) ms | | 3/0/0 |
| read/do/in_flight:1 | libiec61850 | 19,944 (IQR 18,598-20,715, range 17,337-21,263) reads/s | p50 45.5 (IQR 42.9-48.1, range 41.4-49.4) us; p99 112 us; server 19.7 us CPU/read (0.39 core); client 0.65 core; connect 0.37 ms; up 1 | 3/0/0 |
| read/do/in_flight:1 | openiec61850 | 17,415 (IQR 16,218-18,333, range 15,220-19,172) reads/s | p50 51.6 (IQR 47.3-56.1, range 47.0-60.5) us; p99 117 us; server 32.4 us CPU/read (0.56 core); client 0.56 core; connect 0.41 ms; up 1 | 4/0/0 |
| read/do/in_flight:16 | libiec61850 | 50,568 (IQR 34,686-51,545, range 17,425-53,408) reads/s | p50 314.6 (IQR 292.6-314.9, range 289.4-320.2) us; p99 515 us; server 9.1 us CPU/read (0.43 core); client 0.97 core; connect 0.41 ms; up 1 | 4/0/0 |
| read/do/in_flight:16 | openiec61850 | 98,127 (IQR 56,778-100,385, range 10,477-110,531) reads/s | p50 133.5 (IQR 132.4-240.4, range 128.5-618.0) us; p99 406 us; server 9.5 us CPU/read (0.94 core); client 0.95 core; connect 0.45 ms; up 1 | 3/0/0 |
| read/do/in_flight:5 | libiec61850 | 60,796 (IQR 54,632-63,181, range 15,332-63,503) reads/s | p50 76.6 (IQR 75.7-78.9, range 70.0-110.7) us; p99 206 us; server 8.7 us CPU/read (0.46 core); client 0.96 core; connect 0.35 ms; up 1 | 3/0/0 |
| read/do/in_flight:5 | openiec61850 | 104,915 (IQR 96,092-105,434, range 14,878-110,576) reads/s | p50 40.6 (IQR 40.4-41.0, range 40.0-93.2) us; p99 149 us; server 9.1 us CPU/read (0.95 core); client 0.96 core; connect 0.45 ms; up 1 | 3/0/0 |
| read/scalar/in_flight:1 | libiec61850 | 23,204 (IQR 20,587-23,542, range 18,290-23,825) reads/s | p50 39.1 (IQR 38.6-43.0, range 38.4-49.9) us; p99 102 us; server 17.5 us CPU/read (0.41 core); client 0.64 core; connect 0.41 ms; up 1 | 3/0/0 |
| read/scalar/in_flight:1 | openiec61850 | 19,432 (IQR 17,060-19,761, range 15,723-20,179) reads/s | p50 45.7 (IQR 45.5-51.8, range 45.3-57.8) us; p99 116 us; server 29.4 us CPU/read (0.56 core); client 0.56 core; connect 0.46 ms; up 1 | 2/0/0 |
| read/scalar/in_flight:16 | libiec61850 | 51,766 (IQR 51,595-54,109, range 51,268-56,092) reads/s | p50 302.6 (IQR 292.0-307.9, range 278.4-312.0) us; p99 492 us; server 8.8 us CPU/read (0.48 core); client 0.97 core; connect 0.37 ms; up 1 | 3/0/0 |
| read/scalar/in_flight:16 | openiec61850 | 104,095 (IQR 102,180-107,287, range 95,976-108,397) reads/s | p50 129.7 (IQR 128.0-130.7, range 127.8-131.3) us; p99 368 us; server 9.1 us CPU/read (0.94 core); client 0.95 core; connect 0.42 ms; up 1 | 3/0/0 |
| read/scalar/in_flight:5 | libiec61850 | 67,642 (IQR 66,785-68,177, range 55,976-69,340) reads/s | p50 71.9 (IQR 71.1-72.2, range 69.1-73.5) us; p99 164 us; server 7.2 us CPU/read (0.49 core); client 0.98 core; connect 0.33 ms; up 1 | 1/0/0 |
| read/scalar/in_flight:5 | openiec61850 | 106,070 (IQR 105,064-108,607, range 98,512-110,709) reads/s | p50 39.6 (IQR 39.3-39.7, range 39.1-39.8) us; p99 142 us; server 9.0 us CPU/read (0.95 core); client 0.96 core; connect 0.44 ms; up 1 | 1/0/0 |

Paired per-round ratio openiec61850 / libiec61850 (median, range), over all samples, then over the rounds where neither sample was noisy:

- associations:1 reads_per_s: 0.684 (0.658-0.777), n=7; clean: 0.735 (0.658-0.777), n=5
- associations:2 reads_per_s: 0.781 (0.590-1.868), n=7; clean: 0.781 (0.746-0.820), n=5
- associations:4 reads_per_s: 2.170 (0.758-4.299), n=7; clean: 2.106 (1.997-2.191), n=4
- client/client_example2_discovery wall_ms_median: 1.000 (0.998-1.000), n=7; clean: 1.000 (0.998-1.000), n=4
- client/client_example4_dataset wall_ms_median: 1.001 (0.505-1.971), n=7; clean: 1.001 (0.505-1.971), n=5
- client/mms_utility_identify wall_ms_median: 1.000 (0.993-1.015), n=7; clean: 1.000 (0.993-1.015), n=3
- client/mms_utility_read wall_ms_median: 1.000 (0.990-1.002), n=7; clean: 0.999 (0.990-1.002), n=4
- read/do/in_flight:1 reads_per_s: 0.831 (0.817-1.045), n=7; clean: 0.874 (0.819-0.930), n=2
- read/do/in_flight:16 reads_per_s: 1.910 (0.601-2.186), n=7; clean: 1.952 (1.910-2.186), n=3
- read/do/in_flight:5 reads_per_s: 1.726 (0.970-2.175), n=7; clean: 1.732 (1.726-1.754), n=3
- read/scalar/in_flight:1 reads_per_s: 0.842 (0.820-0.860), n=7; clean: 0.838 (0.820-0.854), n=4
- read/scalar/in_flight:16 reads_per_s: 2.011 (1.711-2.114), n=7; clean: 2.080 (2.079-2.114), n=3
- read/scalar/in_flight:5 reads_per_s: 1.568 (1.549-1.760), n=7; clean: 1.564 (1.549-1.672), n=6

Samples: 203, noisy: 72 (foreign use of the pinned CPUs above 0.1 core). Foreign use of the whole machine, in cores: median 0.93, max 19.39.
