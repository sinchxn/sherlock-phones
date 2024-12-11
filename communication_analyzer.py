from collections import Counter
from datetime import datetime

class CommunicationAnalyzer:
    def analyze_communications(self, data):
        analysis = {
            'calls': self._analyze_calls(data['communications']['calls']),
            'messages': self._analyze_messages(data['communications']['messages']),
            'international_activity': self._analyze_international_activity(data['communications']),
            'time_span': self._analyze_time_span(data['communications'])
        }
        return analysis

    def _analyze_calls(self, calls):
        analysis = {
            'total_calls': len(calls),
            'call_types': Counter(call['type'] for call in calls),
            'duration_stats': self._calculate_duration_stats(calls),
            'hourly_distribution': self._get_hourly_distribution(calls),
            'frequent_numbers': self._get_frequent_contacts(calls)
        }
        return analysis

    def _analyze_messages(self, messages):
        analysis = {
            'total_messages': len(messages),
            'message_types': Counter(msg['type'] for msg in messages),
            'hourly_distribution': self._get_hourly_distribution(messages),
            'frequent_contacts': self._get_frequent_contacts(messages)
        }
        return analysis

    def _calculate_duration_stats(self, calls):
        durations = [int(call['duration']) for call in calls if 'duration' in call]
        if not durations:
            return {'avg': 0, 'max': 0, 'min': 0}
        
        return {
            'avg': sum(durations) / len(durations),
            'max': max(durations),
            'min': min(durations)
        }

    def _get_hourly_distribution(self, events):
        hours = Counter()
        for event in events:
            time = datetime.strptime(event['date'], '%Y-%m-%d %H:%M:%S')
            hours[time.hour] += 1
        return dict(hours)

    def _get_frequent_contacts(self, events):
        contacts = Counter(event['number'] for event in events if 'number' in event)
        return dict(contacts.most_common(10))

    def _analyze_time_span(self, communications):
        dates = []
        for msg in communications['messages']:
            dates.append(datetime.strptime(msg['date'], '%Y-%m-%d %H:%M:%S'))
        for call in communications['calls']:
            dates.append(datetime.strptime(call['date'], '%Y-%m-%d %H:%M:%S'))
        
        if dates:
            return {
                'earliest': min(dates).strftime('%Y-%m-%d %H:%M:%S'),
                'latest': max(dates).strftime('%Y-%m-%d %H:%M:%S'),
                'span_days': (max(dates) - min(dates)).days
            }
        return None

    def _analyze_international_activity(self, communications):
        international = {
            'detected': False,
            'countries': set(),
            'details': []
        }
        
        for msg in communications['messages']:
            content = msg['content'].lower()
            if 'welcome to' in content and 'united states' in content:
                international['detected'] = True
                international['countries'].add('United States')
                international['details'].append({
                    'type': 'Welcome Message',
                    'date': msg['date'],
                    'country': 'United States'
                })
        
        return international