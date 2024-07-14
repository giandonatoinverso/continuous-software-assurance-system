import subprocess
import shutil
import requests
import os


class Helper:
    def clone_repository(self, git_url, dest_path, access_token=None):
        if access_token is not None:
            git_url = git_url.replace('https://', f'https://oauth2:{access_token}@')

        clone_command = f"git clone {git_url} {dest_path}"
        subprocess.Popen(clone_command, shell=True).wait()

    def download_file(self, url, dest_path, access_token=None):
        headers = {}
        if access_token is not None:
            headers['PRIVATE-TOKEN'] = access_token

        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(dest_path, "wb") as file:
                file.write(response.content)
        except requests.exceptions.RequestException as e:
            print(f"Error during download: {e}")

    def remove_path_contents(self, dir_path):
        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
            except OSError as e:
                print(f"Error removing {item_path}: {e}")