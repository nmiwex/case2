import os


def extract_artifacts(filename):
    artifacts = set()

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

            artifacts.add(line)

    return artifacts


def compare_all():
    inputs = [name for name in os.listdir()
            if os.path.isfile(name)
            and name.startswith('result')]
    for i in inputs:
        #base_file = "result1.txt"
        base_artifacts = extract_artifacts(i)
        print(f"\nКоманда {inputs.index(i) + 1} нашла: {len(base_artifacts)} артефактов\n")

    print("=" * 60)
    print("СРАВНЕНИЕ КОМАНД")
    print("=" * 60)



    for i in range(2, 11):
        filename = f"result{i}.txt"

        if not os.path.exists(filename):
            continue

        team_artifacts = extract_artifacts(filename)

        common = base_artifacts & team_artifacts
        only_base = base_artifacts - team_artifacts
        only_other = team_artifacts - base_artifacts

        print("-" * 60)
        print(f"Сравнение result1.txt и {filename}")
        print(f"У них найдено: {len(team_artifacts)}")
        print(f"Общие артефакты: {len(common)}")
        print(f"Мы нашли, они нет: {len(only_base)}")
        print(f"Они нашли, мы нет: {len(only_other)}")

        if only_other:
            print("\nПотери нашей команды:")
            for item in sorted(only_other):
                print(item)

    print("\n" + "=" * 60)
    print("Сравнение завершено")
    print("=" * 60)


if __name__ == "__main__":
    compare_all()