def info(text):
    print(
        "\n[\033[1m\033[32m+\033[0m] {}".format(
            text
        )
    )


def prompt(text, lowercase=True):
    question = raw_input(
        "\n[\033[1m\033[36m?\033[0m] {}: ".format(
            text
        )
    )
    if lowercase:
        return question.lower()
    return question


def error(text):
    print(
        "\n[\033[1m\033[31m!\033[0m] {}".format(
            text
        )
    )


def warning(text):
    print(
        "\n[\033[1m\033[33m-\033[0m] {}".format(
            text
        )
    )
