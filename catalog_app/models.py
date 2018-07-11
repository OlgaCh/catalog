from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    """
    Represents User entity. To grant permissions on entry creation/edit/delete
    """
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture_url = Column(String(250))


class Category(Base):
    """
    Main information on the categories
    """
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }


class PlaceItem(Base):
    """
    City places with some information. Linked to category.
    """
    __tablename__ = 'place'

    name = Column(String(160), nullable=False)
    id = Column(Integer, primary_key=True)
    address = Column(String(250))
    phone = Column(String(20))
    website = Column(String(40))
    latitude = Column(Float)
    longitude = Column(Float)
    description = Column(String(750))
    media_links = Column(String(250))
    rating = Column(Float)
    date_created = Column(DateTime)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'address': self.address,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'phone': self.phone,
            'website': self.website,
            'description': self.description,
            'media': self.media_links,
            'rating': self.rating,
            'date_created': self.date_created,
            'id': self.id,
        }


engine = create_engine('sqlite:///places.db')


Base.metadata.create_all(engine)