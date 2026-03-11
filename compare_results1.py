import os


def extract_artifacts(filename):
    artifacts = []

    if not os.path.exists(filename):
        return artifacts

    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            if (
                not line or
                line.startswith('=') or
                line.startswith('-') or
                line.startswith('✰') or
                line.endswith(':') or
                "ОТЧЕТ" in line or
                "КОНЕЦ ОТЧЕТА" in line or
                "Найдено артефактов" in line
            ):
                continue

            artifacts.append(line)

    return artifacts


def compare_all():

    inputs = [name for name in os.listdir()
              if os.path.isfile(name)
              and name.startswith('result')
              and name.endswith('.txt')]

    inputs.sort(key=lambda x: int(''.join(filter(str.isdigit, x)) or 0))

    print("=" * 60)
    print("СРАВНЕНИЕ КОМАНД")
    print("=" * 60)

    for i, filename in enumerate(inputs, 1):
        artifacts = extract_artifacts(filename)
        print(f"Команда {i} ({filename}): {len(artifacts)} артефактов")

    print()

    for i in range(len(inputs) - 1):
        file1 = inputs[i]
        file2 = inputs[i + 1]

        artifacts1 = extract_artifacts(file1)
        artifacts2 = extract_artifacts(file2)

        common = [art for art in artifacts1 if art in artifacts2]
        only_first = [art for art in artifacts1 if art not in artifacts2]
        only_second = [art for art in artifacts2 if art not in artifacts1]

        print("-" * 60)
        print(f"Сравнение {file1} и {file2}")
        print(f"{file1}: {len(artifacts1)} артефактов")
        print(f"{file2}: {len(artifacts2)} артефактов")
        print(f"Общие артефакты: {len(common)}")
        print(f"Только в {file1}: {len(only_first)}")
        print(f"Только в {file2}: {len(only_second)}")

        if only_first:
            print(f"\nЕсть в {file1}, нет в {file2}:")
            for item in sorted(only_first):
                print(f"  {item}")

        if only_second:
            print(f"\nЕсть в {file2}, нет в {file1}:")
            for item in sorted(only_second):
                print(f"  {item}")

    print("\n" + "=" * 60)
    print("Сравнение завершено")
    print("=" * 60)


if __name__ == "__main__":
    compare_all()