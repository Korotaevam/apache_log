from collections import Counter

from flask import Flask, render_template, request
from apache_log_parser import make_parser
import pandas as pd

app = Flask(__name__)


def parse_log_file(file):
    try:
        parser = make_parser('%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"')

        with open(file, 'r') as f:
            logs = f.readlines()
            parsed_logs = [parser(line) for line in logs]
        # Преобразуем данные в DataFrame
        df = pd.DataFrame(parsed_logs)

        return df

    except:
        print(f"Failed to parse log file")
        return None


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']

        if file:
            file_path = f"{file.filename}"
            df = parse_log_file(file_path)

            if df is not None:
                # all
                data = df.to_dict()
                data_list = list(
                    zip(data['remote_host'], data['remote_host'].values(), data['request_method'].values(),
                        data['request_header_referer'].values(),
                        data['status'].values(), data['time_received_datetimeobj'].values(),
                        data['request_header_user_agent'].values()))

                # ban
                ban = []
                i = 0
                data_ban = list(data['remote_host'].values())
                res = Counter(data_ban).most_common(10)

                for key, val in res:
                    if val > 5:
                        ban.append({'N': i, 'ip': key, 'frequency': val})
                        i += 1

                return render_template('index.html', data=data_list, ban=ban)

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
