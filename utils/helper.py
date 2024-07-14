import subprocess


class Helper:
    def clone_repository(self, git_url, local_path, access_token=None):
        if access_token is not None:
            git_url = git_url.replace('https://', f'https://oauth2:{access_token}@')

        clone_command = f"git clone {git_url} {local_path}"
        subprocess.Popen(clone_command, shell=True).wait()
