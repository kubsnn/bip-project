# BIP Project - masked EMV Track 1/2 reader

Projekt laboratoryjny z przedmiotu Bezpieczenstwo w Internecie Przedmiotow.
Skrypt laczy sie z czytnikiem PC/SC, wybiera aplikacje EMV na karcie i szuka
danych Track 1 oraz Track 2 w publicznych rekordach aplikacji.

## Cel

Celem projektu jest pokazanie kontrolowanego odczytu danych Track 1/2.

Skrypt wyszukuje:

- Track 1: tag EMV `56`
- Track 2: tagi EMV `57` oraz `9F6B`

## Wymagania

- Windows z dzialajaca usluga Smart Card / PC/SC
- czytnik PC/SC, np. OMNIKEY
- Python 3
- karta testowa EMV

Skrypt korzysta z `ctypes` i systemowej biblioteki `winscard.dll`, wiec nie
wymaga dodatkowych pakietow Pythona.

## Uruchomienie

W katalogu projektu:

```powershell
py main.py
```

Jesli w systemie jest kilka czytnikow, mozna wskazac fragment nazwy:

```powershell
py main.py --reader OMNIKEY
```

Domyslny plik wynikowy:

```text
trlog_output.json
```

## Przykladowy output

```json
{
  "tracks_found": true,
  "track1_count": 0,
  "track2_count": 1,
  "tracks": [
    {
      "track": "track2",
      "tag": "57",
      "sfi": 1,
      "record": 2,
      "track2_equivalent": {
        "parse_status": "ok",
        "raw_length_bytes": *,
        "separator": "*",
        "track2_masked": "************************************",
        "pan_masked": "*****************",
        "pan_length": *,
        "expiry_yymm_masked": "****",
        "service_code_masked": "***",
        "discretionary_len": *,
        "discretionary_masked": "*******"
      }
    }
  ]
}
```

## Jak to dziala

1. Skrypt laczy sie z czytnikiem przez PC/SC.
2. Wybiera aplikacje platnicza przez PSE lub liste znanych AID.
3. Wysyla `GET PROCESSING OPTIONS`.
4. Z odpowiedzi pobiera AFL, czyli liste rekordow do odczytu.
5. Czyta tylko rekordy wskazane przez AFL.
6. Parsuje TLV i wyszukuje tagi `56`, `57` oraz `9F6B`.
7. Przed zapisem do JSON maskuje wartosci Track 1/2.

## Zabezpieczenia w outputcie


Wynik jest celowo ograniczony do informacji potrzebnych do demonstracji:
czy track zostal znaleziony, w ktorym tagu i rekordzie, oraz jaka jest jego
zamaskowana postac.

## Pliki

- `main.py` - glowny skrypt projektu
- `trlog_output.json` - domyslny plik wynikowy generowany po uruchomieniu

## Uwagi

Track 1 nie zawsze jest dostepny na kartach EMV. W takim przypadku
`track1_count` moze wynosic `0`, co jest poprawnym wynikiem.
