import os
import pandas as pd
import glob
import pathlib

data_dir = "../Data/Dataset_1/Dataset"
output_file = "../Data/Dataset_1_labelled.csv"


def get_labels_from_path(path):
    folder = pathlib.Path(path)
    return folder.parent.name


def create_csv_from_sol_files():
    data = []

    # Récupérer tous les types de vulnérabilités (noms des répertoires)
    vulnerability_types = [os.path.basename(d) for d in glob.glob(os.path.join(data_dir, "*")) if os.path.isdir(d)]

    # Parcourir tous les répertoires de vulnérabilités
    for category_dir in glob.glob(os.path.join(data_dir, "*")):
        if os.path.isdir(category_dir):
            category_label = os.path.basename(category_dir)

            # Trouver tous les fichiers .sol dans ce répertoire
            for sol_file in glob.glob(os.path.join(category_dir, "*.sol")):
                file_name = os.path.basename(sol_file)

                # Lire le contenu du fichier
                try:
                    with open(sol_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception as e:
                    print(f"Erreur lors de la lecture de {sol_file}: {e}")
                    content = ""

                # Créer une entrée avec colonnes booléennes pour chaque type
                entry = {
                    'file': sol_file,
                    'content': content
                }

                # Ajouter une colonne True/False pour chaque type de vulnérabilité
                for vuln_type in vulnerability_types:
                    entry[vuln_type] = (vuln_type == category_label)

                data.append(entry)

    # Créer et sauvegarder le DataFrame
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    print(f"CSV créé : {output_file}")
    print(f"Nombre de fichiers : {len(df)}")
    print(f"Types de vulnérabilités : {vulnerability_types}")

    return df


# Exécuter
if __name__ == "__main__":
    create_csv_from_sol_files()