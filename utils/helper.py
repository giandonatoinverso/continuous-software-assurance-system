import subprocess
import shutil
import requests


class Helper:
    def clone_repository(self, git_url, dest_path, access_token=None):
        if access_token is not None:
            git_url = git_url.replace('https://', f'https://oauth2:{access_token}@')

        clone_command = f"git clone {git_url} {dest_path}"
        subprocess.Popen(clone_command, shell=True).wait()

    def download_file(self, url, dest_path):
        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(dest_path, "wb") as file:
                file.write(response.content)
        except requests.exceptions.RequestException as e:
            print(f"Error during download: {e}")

    def remove_path(self, file_path):
        try:
            shutil.rmtree(file_path)
        except OSError as e:
            print(f"Error removing folder {file_path}: {e}")