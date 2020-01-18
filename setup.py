from distutils.core import setup

setup(name="ecpy",
      version="1.0.4",
      description="A Elliptic-Curve Library",
      author="@elliptic_shiho",
      author_email="shiho.elliptic@gmaill.com",
      url="https://github.com/elliptic-shiho/ecpy/",
      packages=["ecpy", "ecpy.fields", "ecpy.rings", "ecpy.utils", "ecpy.elliptic_curve"],
      install_requires=["six"]
      )
