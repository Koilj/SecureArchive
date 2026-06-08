import re

def clean_text(text):
    """
    Базовая очистка: убираем лишние пробелы и непечатные символы.
    """
    if not isinstance(text, str):
        return ""
    # Убираем символы переноса строк и табуляции
    text = re.sub(r'\s+', ' ', text)
    # Убираем явный мусор, но оставляем пунктуацию (важна для контекста)
    text = text.strip()
    return text

def format_model_input(title, authors, abstract, keywords=""):
    """
    Формирует богатый контекст для модели.
    Формат: [CLS] TITLE [SEP] AUTHORS [SEP] KEYWORDS [SEP] ABSTRACT [SEP]
    """
    parts = [
        str(title or "").strip(),
        str(authors or "").strip(),
        str(keywords or "").strip(),
        str(abstract or "").strip()
    ]
    # Убираем пустые части
    parts = [p for p in parts if p]
    return " [SEP] ".join(parts)