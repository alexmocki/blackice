from blackice.detections.rules.stuffing_burst import StuffingBurstDetector
from blackice.detections.rules.token_reuse import TokenReuseDetector
from blackice.detections.rules.impossible_travel import ImpossibleTravelDetector


def main() -> None:
    events = [
        # stuffing burst
        {"ts": "2025-12-17T21:00:00Z", "event_type": "login_fail", "src_ip": "1.1.1.1", "user_id": "u1"},
        {"ts": "2025-12-17T21:00:05Z", "event_type": "login_fail", "src_ip": "1.1.1.1", "user_id": "u1"},
        {"ts": "2025-12-17T21:00:10Z", "event_type": "login_fail", "src_ip": "1.1.1.1", "user_id": "u1"},

        # token reuse across device/country
        {"ts": "2025-12-17T21:10:00Z", "event_type": "api_call", "src_ip": "2.2.2.2", "user_id": "u2",
         "auth_method": "token", "token_id": "t-abc", "device_id": "d2", "country": "US"},
        {"ts": "2025-12-17T21:10:30Z", "event_type": "api_call", "src_ip": "3.3.3.3", "user_id": "u2",
         "auth_method": "token", "token_id": "t-abc", "device_id": "d9", "country": "FR"},

        # impossible travel (same user, different countries too close)
        {"ts": "2025-12-17T22:00:00Z", "event_type": "api_call", "src_ip": "4.4.4.4", "user_id": "u3",
         "auth_method": "token", "token_id": "t-u3", "device_id": "mac-1", "country": "US"},
        {"ts": "2025-12-17T22:20:00Z", "event_type": "api_call", "src_ip": "5.5.5.5", "user_id": "u3",
         "auth_method": "token", "token_id": "t-u3", "device_id": "win-7", "country": "JP"},
    ]

    det1 = StuffingBurstDetector(window_seconds=60, fail_threshold=3)
    det2 = TokenReuseDetector(window_seconds=3600, min_distinct_devices=2, min_distinct_countries=2)
    det3 = ImpossibleTravelDetector(window_seconds=6 * 3600)

    for e in events:
        for a in det1.process(e):
            print(a)
        for a in det2.process(e):
            print(a)
        for a in det3.process(e):
            print(a)


if __name__ == "__main__":
    main()
